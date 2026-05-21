package engine

import (
	"context"
	"io"
	"net/http"
	"sync"

	"dast-fuzzer/internal/client"
	"dast-fuzzer/internal/payload"
)

type FuzzJob struct {
	TargetURL   string
	TargetParam string
	Payload     string
}

type FuzzResult struct {
	Payload     string
	InjectedURL string
	StatusCode  int
	BodyLength  int
	Body        string
}

func worker(ctx context.Context, fc *client.FuzzClient, jobs <-chan FuzzJob, results chan<- FuzzResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		injectedURL, err := payload.InjectQueryParam(job.TargetURL, job.TargetParam, job.Payload)
		if err != nil {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", injectedURL, nil)
		if err != nil {
			continue
		}

		resp, err := fc.DoRequest(ctx, req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		results <- FuzzResult{
			Payload:     job.Payload,
			InjectedURL: injectedURL,
			StatusCode:  resp.StatusCode,
			BodyLength:  len(body),
			Body:        string(body),
		}
	}
}

func RunFuzzer(ctx context.Context, targetURL string, targetParam string, payloads []string, numWorkers int, fc *client.FuzzClient) []FuzzResult {
	numJobs := len(payloads)
	jobs := make(chan FuzzJob, numJobs)
	results := make(chan FuzzResult, numJobs)

	var wg sync.WaitGroup

	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(ctx, fc, jobs, results, &wg)
	}

	for _, p := range payloads {
		jobs <- FuzzJob{
			TargetURL:   targetURL,
			TargetParam: targetParam,
			Payload:     p,
		}
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	var finalResults []FuzzResult
	for res := range results {
		finalResults = append(finalResults, res)
	}

	return finalResults
}
