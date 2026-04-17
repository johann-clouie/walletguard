package main

import (
	"context"
	"log"
	"os/signal"
	"sync"
	"syscall"

	"github.com/example/walletguard/config"
	"github.com/example/walletguard/internal/alert"
	"github.com/example/walletguard/internal/connectors"
	"github.com/example/walletguard/internal/detectors"
	"github.com/example/walletguard/internal/domain"
	"github.com/example/walletguard/internal/enrichment"
	"github.com/example/walletguard/internal/incidents"
	"github.com/example/walletguard/internal/ingest"
	"github.com/example/walletguard/internal/pipeline"
	"github.com/example/walletguard/internal/storage"
)

func main() {
	cfg := config.Load()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store, err := storage.ConnectPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer store.Close()

	var conns []connectors.Connector
	for _, root := range cfg.ScanRoots {
		conns = append(conns, &connectors.FilesystemConnector{Roots: []string{root}, Name: "fs:" + root})
	}
	for _, p := range cfg.GitRepoPaths {
		conns = append(conns, &connectors.GitConnector{RepoPaths: []string{p}, Name: "git:" + p})
	}
	if cfg.S3LocalPath != "" {
		conns = append(conns, &connectors.S3LocalConnector{LocalRoot: cfg.S3LocalPath, Bucket: "local"})
	}
	if len(conns) == 0 {
		log.Fatal("set SCAN_ROOTS and/or GIT_REPO_PATHS and/or S3_LOCAL_PATH")
	}

	eng := detectors.NewEngine()
	enr := enrichment.NewBalanceChecker(cfg.EVMRPCURL, cfg.SolanaRPCURL)
	proc := &pipeline.ProcessDocument{
		Store:     store,
		Enrich:    enr,
		Notifier:  alert.NewNotifier(cfg.SlackWebhookURL),
		Incidents: &incidents.Manager{},
	}

	sem := make(chan struct{}, cfg.WorkerConcurrency)
	var wg sync.WaitGroup

	for _, c := range conns {
		c := c
		srcID, err := store.EnsureSource(ctx, c.Name(), c.Type())
		if err != nil {
			log.Fatalf("source %s: %v", c.Name(), err)
		}
		docs := make(chan domain.Document, 64)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Scan(ctx, docs); err != nil && err != context.Canceled {
				log.Printf("connector %s: %v", c.Name(), err)
			}
			close(docs)
		}()
		for doc := range docs {
			doc := doc
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				dbDocID, err := store.InsertDocument(ctx, srcID, doc)
				if err != nil {
					log.Printf("document %s: %v", doc.Path, err)
					return
				}
				chunks := ingest.Chunk(doc, cfg.ChunkSizeBytes)
				var all []domain.Finding
				for _, ch := range chunks {
					all = append(all, eng.Scan(ch)...)
				}
				all = dedupeFindings(all)
				if len(all) == 0 {
					return
				}
				if err := proc.Handle(ctx, dbDocID, doc, all); err != nil {
					log.Printf("pipeline %s: %v", doc.Path, err)
				}
			}()
		}
	}
	wg.Wait()
	log.Println("scan complete")
}

func dedupeFindings(in []domain.Finding) []domain.Finding {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, f := range in {
		key := string(f.SecretType) + "|" + string(f.RawSnippet)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
