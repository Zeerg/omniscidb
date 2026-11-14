// Normalize the complete EPSS archive without keeping score history in memory.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const nullValue = "__VULN_NULL__"

type Source struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Date string `json:"date"`
}

type Day struct {
	Date              string `json:"date"`
	Model             string `json:"model"`
	Beta              bool   `json:"beta"`
	Rows              int64  `json:"rows"`
	Sum               int64  `json:"score_sum_ppb"`
	Above1            int64  `json:"above_1pct"`
	Above10           int64  `json:"above_10pct"`
	Above50           int64  `json:"above_50pct"`
	Above90           int64  `json:"above_90pct"`
	MissingPercentile int64  `json:"missing_percentile"`
}

type Output struct {
	Path string `json:"path"`
	Rows int64  `json:"rows"`
	Beta bool   `json:"beta"`
}

func convert(root, group string, files []Source) (Output, []Day, error) {
	path := filepath.Join(root, "normalized", "epss_"+group+".csv.gz")
	out, err := os.Create(path + ".partial")
	if err != nil {
		return Output{}, nil, err
	}
	defer out.Close()
	zipped, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		return Output{}, nil, err
	}
	writer := csv.NewWriter(zipped)
	if err = writer.Write([]string{"cve_id", "score_date", "epss", "percentile", "epss_ppb", "percentile_ppb", "model_version", "is_beta"}); err != nil {
		return Output{}, nil, err
	}
	result := Output{Path: path, Beta: group == "beta"}
	days := []Day{}
	for _, source := range files {
		day, err := convertDay(filepath.Join(root, source.Path), source, writer)
		if err != nil {
			return result, days, err
		}
		result.Rows += day.Rows
		days = append(days, day)
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		return result, days, err
	}
	if err = zipped.Close(); err != nil {
		return result, days, err
	}
	if err = out.Close(); err != nil {
		return result, days, err
	}
	if err = os.Rename(path+".partial", path); err != nil {
		return result, days, err
	}
	return result, days, nil
}

func convertDay(path string, source Source, writer *csv.Writer) (Day, error) {
	day := Day{Date: source.Date, Model: "v1", Beta: source.Kind == "epss_beta"}
	file, err := os.Open(path)
	if err != nil {
		return day, err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return day, err
	}
	defer compressed.Close()
	buffer := bufio.NewReaderSize(compressed, 1024*1024)
	for {
		first, err := buffer.Peek(1)
		if err != nil {
			return day, err
		}
		if first[0] != '#' {
			break
		}
		line, err := buffer.ReadString('\n')
		if err != nil {
			return day, err
		}
		for _, field := range strings.Split(strings.TrimSpace(line), ",") {
			field = strings.TrimPrefix(field, "#")
			if strings.HasPrefix(field, "model_version:") {
				day.Model = strings.TrimPrefix(field, "model_version:")
			}
			if strings.HasPrefix(field, "score_date:") && !strings.HasPrefix(strings.TrimPrefix(field, "score_date:"), source.Date) {
				return day, fmt.Errorf("date mismatch in %s", path)
			}
		}
	}
	reader := csv.NewReader(buffer)
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil {
		return day, err
	}
	if len(header) < 2 || header[0] != "cve" || header[1] != "epss" || (len(header) > 2 && header[2] != "percentile") {
		return day, fmt.Errorf("unexpected header in %s: %v", path, header)
	}
	row := [8]string{}
	row[1], row[6], row[7] = source.Date, day.Model, strconv.FormatBool(day.Beta)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return day, fmt.Errorf("%s: %w", path, err)
		}
		if len(record[0]) < 13 || !strings.HasPrefix(record[0], "CVE-") || record[0][8] != '-' {
			return day, fmt.Errorf("invalid CVE in %s: %s", path, record[0])
		}
		_, yearError := strconv.ParseUint(record[0][4:8], 10, 16)
		_, serialError := strconv.ParseUint(record[0][9:], 10, 64)
		if yearError != nil || serialError != nil {
			return day, fmt.Errorf("invalid CVE: %s", record[0])
		}
		score, err := strconv.ParseFloat(record[1], 64)
		if err != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			return day, fmt.Errorf("invalid probability in %s", path)
		}
		ppb := int64(math.Round(score * 1e9))
		row[0], row[2], row[3], row[4], row[5] = record[0], record[1], nullValue, strconv.FormatInt(ppb, 10), nullValue
		if len(record) > 2 && record[2] != "" {
			percentile, err := strconv.ParseFloat(record[2], 64)
			if err != nil || math.IsNaN(percentile) || math.IsInf(percentile, 0) || percentile < 0 || percentile > 1 {
				return day, fmt.Errorf("invalid percentile in %s", path)
			}
			row[3], row[5] = record[2], strconv.FormatInt(int64(math.Round(percentile*1e9)), 10)
		} else {
			day.MissingPercentile++
		}
		if err := writer.Write(row[:]); err != nil {
			return day, err
		}
		day.Rows++
		day.Sum += ppb
		if ppb >= 10000000 {
			day.Above1++
		}
		if ppb >= 100000000 {
			day.Above10++
		}
		if ppb >= 500000000 {
			day.Above50++
		}
		if ppb >= 900000000 {
			day.Above90++
		}
	}
	if day.Rows == 0 {
		return day, fmt.Errorf("empty score file: %s", path)
	}
	return day, nil
}

func main() {
	root := flag.String("data", "build-macos/vulnerability-data", "download directory")
	flag.Parse()
	bytes, err := os.ReadFile(filepath.Join(*root, "sources.json"))
	if err != nil {
		panic(err)
	}
	var manifest struct {
		Items []Source `json:"items"`
	}
	if err = json.Unmarshal(bytes, &manifest); err != nil {
		panic(err)
	}
	groups := map[string][]Source{}
	for _, source := range manifest.Items {
		if source.Kind != "epss" && source.Kind != "epss_beta" {
			continue
		}
		group := source.Date[:4]
		if source.Kind == "epss_beta" {
			group = "beta"
		}
		groups[group] = append(groups[group], source)
	}
	if err = os.MkdirAll(filepath.Join(*root, "normalized"), 0755); err != nil {
		panic(err)
	}
	var mutex sync.Mutex
	var tasks sync.WaitGroup
	outputs := []Output{}
	days := []Day{}
	errors := []error{}
	for group, files := range groups {
		tasks.Add(1)
		go func(group string, files []Source) {
			defer tasks.Done()
			sort.Slice(files, func(i, j int) bool { return files[i].Date < files[j].Date })
			output, history, err := convert(*root, group, files)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				errors = append(errors, err)
				return
			}
			outputs = append(outputs, output)
			days = append(days, history...)
			fmt.Printf("Normalized %s: %d rows from %d files\n", group, output.Rows, len(files))
		}(group, files)
	}
	tasks.Wait()
	if len(errors) > 0 {
		panic(errors[0])
	}
	sort.Slice(days, func(i, j int) bool {
		if days[i].Date == days[j].Date {
			return !days[i].Beta && days[j].Beta
		}
		return days[i].Date < days[j].Date
	})
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Path < outputs[j].Path })
	result := struct {
		Outputs []Output `json:"outputs"`
		Days    []Day    `json:"days"`
	}{outputs, days}
	bytes, err = json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(filepath.Join(*root, "epss-normalization.json"), append(bytes, '\n'), 0644); err != nil {
		panic(err)
	}
	fmt.Printf("PASS: normalized %d daily files\n", len(days))
}
