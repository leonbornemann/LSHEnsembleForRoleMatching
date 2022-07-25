package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/ekzhu/lshensemble"
	"log"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Users struct which contains
// an array of users
type Role struct {
	ID     string
	Values []string
}

func readLinebyLine(filepath string) ([]string, []map[string]bool) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example

	const maxCapacity = 10000000 // your required line length
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)
	// append works on nil slices.

	var domains []map[string]bool
	var keys []string
	for scanner.Scan() {
		var res = scanner.Bytes()
		var role Role
		json.Unmarshal(res, &role)
		keys = append(keys, role.ID)
		var domain = make(map[string]bool)
		for i := range role.Values {
			domain[role.Values[i]] = true
		}
		domains = append(domains, domain)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return keys, domains
}

func main() {
	start := time.Now()
	log.Printf("Beginning execution")
	fmt.Println(os.Args)
	inputFilePathIndex := os.Args[1]
	inputFilePathQuery := os.Args[2] //set query equal to index for mode "rm"
	var resultDir = os.Args[3]
	var threshold, _ = strconv.ParseFloat(os.Args[4], 64) //containment threshold
	var mode = os.Args[5]                                 //choose RM or RCBRB
	var indexKeys, indexDomains = readLinebyLine(inputFilePathIndex)
	var queryKeys, queryDomains = readLinebyLine(inputFilePathQuery)
	var keyToIndexMap = make(map[string]int)
	for i := range indexKeys {
		keyToIndexMap[indexKeys[i]] = i
		//fmt.Println(indexKeys[i], indexDomains[i])
	}

	// set the number of hash functions
	numHash := 256
	indexDomainRecords := createDomainRecords(indexDomains, indexKeys, numHash)
	queryDomainRecords := createDomainRecords(queryDomains, queryKeys, numHash)

	// Set the number of partitions
	numPart := 8

	// Set the maximum value for the MinHash LSH parameter K
	// (number of hash functions per band).
	maxK := 4

	fmt.Println("Building Index")
	// Create index using equi-depth partitioning
	// You can also use BootstrapLshEnsemblePlusEquiDepth for better accuracy
	index_eqd, err := lshensemble.BootstrapLshEnsembleEquiDepth(numPart, numHash, maxK,
		len(indexDomainRecords), lshensemble.Recs2Chan(indexDomainRecords))
	if err != nil {
		panic(err)
	}

	// Create index using optimal partitioning
	// You can also use BootstrapLshEnsemblePlusOptimal for better accuracy
	//index_opt, err := lshensemble.BootstrapLshEnsembleOptimal(numPart, numHash, maxK,
	//	func() <-chan *lshensemble.DomainRecord {
	//		return lshensemble.Recs2Chan(indexDomainRecords)
	//	})
	//if err != nil {
	//	panic(err)
	//}

	fmt.Println("Beginning Querying")

	// pick a domain to use as the query
	fmt.Println("Found ", len(indexDomainRecords), "indexDomains to query - begin querying")
	if mode == "sample" {
		resultFile, err := os.Create(resultDir + "/results.csv")
		if err != nil {
			log.Fatal(err)
		}
		drawSample(indexDomainRecords, indexKeys, index_eqd, indexDomains, keyToIndexMap, threshold, resultFile)
	} else if mode == "rm" {
		doFullBlocking(indexDomainRecords, indexKeys, index_eqd, indexDomains, queryDomains, keyToIndexMap, threshold, resultDir)
	} else {
		doFullBlocking(queryDomainRecords, queryKeys, index_eqd, indexDomains, queryDomains, keyToIndexMap, threshold, resultDir)
	}
	elapsed := time.Since(start)
	log.Printf("Application took %s", elapsed)
}

func createDomainRecords(indexDomains []map[string]bool, indexKeys []string, numHash int) []*lshensemble.DomainRecord {
	// initializing the domain records to hold the MinHash signatures
	domainRecords := make([]*lshensemble.DomainRecord, len(indexDomains))

	// set the minhash seed
	var seed int64 = 42
	rand.Seed(seed)

	// create the domain records with the signatures
	for i := range indexDomains {
		mh := lshensemble.NewMinhash(seed, numHash)
		for v := range indexDomains[i] {
			mh.Push([]byte(v))
		}
		domainRecords[i] = &lshensemble.DomainRecord{
			Key:       indexKeys[i],
			Size:      len(indexDomains[i]),
			Signature: mh.Signature()}
	}
	sort.Sort(lshensemble.BySize(domainRecords))
	return domainRecords
}

func ToSlice(c <-chan interface{}) []interface{} {
	s := make([]interface{}, 0)
	for i := range c {
		s = append(s, i)
	}
	return s
}

func drawSample(domainRecords []*lshensemble.DomainRecord,
	keys []string,
	index_eqd *lshensemble.LshEnsemble,
	domains []map[string]bool,
	keyToIndexMap map[string]int,
	threshold float64,
	resultFile *os.File) {
	var sampled = 0
	var chosen = make(map[string]bool)
	for sampled < 500 {
		var queryIndex = rand.Intn(len(domainRecords))
		queryKey := keys[queryIndex]
		//fmt.Println("Querying ", queryKey)
		querySig := domainRecords[queryIndex].Signature
		querySize := domainRecords[queryIndex].Size

		// get the keys of the candidate domains (may contain false positives)
		// through a channel with option to cancel early.
		done := make(chan struct{})
		defer close(done) // Important!!
		results := index_eqd.Query(querySig, querySize, threshold, done)
		var resultsAsSlice = ToSlice(results)
		var queryDomain = domains[queryIndex]
		var resultIndex = rand.Intn(len(resultsAsSlice))
		var keyAsString = resultsAsSlice[resultIndex].(string)
		var keyIndex = keyToIndexMap[keyAsString]
		//compute actual overlap:
		var resultDomain = domains[keyIndex]
		var overlap = computeActualOverlap(queryDomain, resultDomain)
		var combinedKey = queryKey + "_" + keyAsString
		if queryKey > keyAsString {
			combinedKey = keyAsString + "_" + queryKey
		}
		var resultAlreadyContained = false
		if _, ok := chosen[combinedKey]; ok {
			resultAlreadyContained = true
		}
		if overlap >= threshold && !resultAlreadyContained && queryKey != keyAsString {
			if queryKey < keyAsString {
				var line = queryKey + "," + keyAsString + "," + fmt.Sprintf("%f", overlap) + "\n"
				resultFile.WriteString(line)
			} else {
				var line = keyAsString + "," + queryKey + "," + fmt.Sprintf("%f", overlap) + "\n"
				resultFile.WriteString(line)
			}
			sampled++
			if sampled == 46 {
				fmt.Println("asd")
			}
			chosen[combinedKey] = true
		} else {
			//fmt.Println("Skipping Match ", queryKey, keyAsString, "cur size", sampled)
		}

	}
}

func doFullBlockingForQueryIndices(
	begin int,
	end int,
	domainRecords []*lshensemble.DomainRecord,
	keys []string,
	index_eqd *lshensemble.LshEnsemble,
	indexDomains []map[string]bool,
	queryDomains []map[string]bool,
	keyToIndexMap map[string]int,
	threshold float64,
	resultFilePath string,
	wg *sync.WaitGroup) {
	defer wg.Done()
	resultFileOS, err := os.Create(resultFilePath)
	if err != nil {
		log.Fatal(err)
	}
	resultFile := bufio.NewWriter(resultFileOS)
	resultFile.WriteString("id1,id2,compatibility\n")
	defer resultFileOS.Close()
	var processed = 0
	//var totalResultCount = 0
	//var lastAverage = 0.0
	//var nStableCounts = 0
	for i := begin; i < end; i++ {
		if processed%1000 == 0 {
			fmt.Println("Processed in range [", begin, end, ") :", processed, "/", end-begin, "(", 100.0*float64(processed)/float64(end-begin), "%)")
		}
		queryKey := keys[i]
		//fmt.Println("Querying ", queryKey)
		querySig := domainRecords[i].Signature
		querySize := domainRecords[i].Size

		// get the keys of the candidate indexDomains (may contain false positives)
		// through a channel with option to cancel early.
		done := make(chan struct{})
		defer close(done) // Important!!
		results := index_eqd.Query(querySig, querySize, threshold, done)
		var queryDomain = queryDomains[i]
		var exactMatchCountThisQuery = 0
		for key := range results {
			var keyAsString = key.(string)
			if queryKey < keyAsString {
				var keyIndex = keyToIndexMap[keyAsString]
				//compute actual overlap:
				var resultDomain = indexDomains[keyIndex]
				var overlap = computeActualOverlap(queryDomain, resultDomain)
				if overlap >= threshold && key != queryKey {
					//var line = strconv.Itoa(i) + "," + strconv.Itoa(keyIndex) + "," + fmt.Sprintf("%f", overlap) + "\n"
					var line = queryKey + "," + keyAsString + "," + fmt.Sprintf("%f", overlap) + "\n"
					resultFile.WriteString(line)
					exactMatchCountThisQuery += 1
				}
			}
		}
		processed++
	}
	resultFile.Flush()
}

func doFullBlocking(domainRecords []*lshensemble.DomainRecord,
	keys []string,
	index_eqd *lshensemble.LshEnsemble,
	indexDomains []map[string]bool,
	queryDomains []map[string]bool,
	keyToIndexMap map[string]int,
	threshold float64,
	resultDir string) {
	//var totalResultCount = 0
	//var lastAverage = 0.0
	//var nStableCounts = 0
	var totalBatchCount = 9
	borderIncrementas := len(domainRecords) / totalBatchCount
	prevEnd := 0
	var wg sync.WaitGroup
	if borderIncrementas == 0 {
		wg.Add(1)
		resultFile := resultDir + "/" + fmt.Sprintf("%d_%d", 0, len(domainRecords))
		doFullBlockingForQueryIndices(0, len(domainRecords), domainRecords, keys, index_eqd, indexDomains, queryDomains, keyToIndexMap, threshold, resultFile, &wg)
	} else {
		for i := 0; i < totalBatchCount; i++ {
			wg.Add(1)
			curBegin := prevEnd
			curEnd := 0
			if i == totalBatchCount-1 {
				curEnd = len(domainRecords)
			} else {
				curEnd = curBegin + borderIncrementas
			}
			//TODO: call goroutine:
			resultFile := resultDir + "/" + fmt.Sprintf("%d_%d", curBegin, curEnd)
			fmt.Println("Creating new Task with result file ", resultFile)
			go doFullBlockingForQueryIndices(curBegin, curEnd, domainRecords, keys, index_eqd, indexDomains, queryDomains, keyToIndexMap, threshold, resultFile, &wg)
			prevEnd = curEnd
		}
		fmt.Println("Avaiting Termination")
		wg.Wait()
		fmt.Println("done")
	}
}

func computeActualOverlap(domain map[string]bool, domain2 map[string]bool) float64 {
	var intersectionCount = 0
	for key, _ := range domain {
		if _, ok := domain2[key]; ok {
			intersectionCount++
		}
	}
	return float64(intersectionCount) / float64(len(domain))
}
