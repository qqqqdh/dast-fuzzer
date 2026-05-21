package payload

import (
	"bufio"
	"net/url"
	"os"
)

func LoadPayloads(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text != "" {
			payloads = append(payloads, text)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return payloads, nil
}

func InjectQueryParam(targetURL string, paramName string, payload string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	q := u.Query()

	if originalValue := q.Get(paramName); originalValue != "" {
		q.Set(paramName, originalValue+payload)
	} else {
		q.Set(paramName, payload)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}
