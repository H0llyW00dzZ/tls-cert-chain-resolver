// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package logger_test

import (
	"bytes"
	"testing"

	"github.com/H0llyW00dzZ/tls-cert-chain-resolver/src/logger"
)

func BenchmarkMCPLogger_Printf(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		log.Printf("Benchmark message %d", i)
	}
}

func BenchmarkMCPLogger_Println(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		log.Println("Benchmark message", i)
	}
}

func BenchmarkMCPLogger_PrintfConcurrent(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			log.Printf("Concurrent message %d", i)
			i++
		}
	})
}

func BenchmarkMCPLogger_PrintlnConcurrent(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			log.Println("Concurrent message", i)
			i++
		}
	})
}

func BenchmarkMCPLogger_Silent(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, true)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		log.Printf("Silent message %d", i)
	}
}

func BenchmarkCLILogger_Printf(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewCLILogger()
	log.SetOutput(&buf)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		log.Printf("Benchmark message %d", i)
	}
}

func BenchmarkMCPLogger_ComplexMessage(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		log.Printf("Processing certificate chain for %s: found %d intermediates, total size %d bytes",
			"example.com", i, i*1024)
	}
}

func BenchmarkMCPLogger_JSONEscaping(b *testing.B) {
	var buf bytes.Buffer
	log := logger.NewMCPLogger(&buf, false)

	msg := `Certificate error: "invalid signature" in chain\nDetails: CN=Test\tO=Example`

	b.ReportAllocs()

	for b.Loop() {
		log.Printf("%s", msg)
	}
}
