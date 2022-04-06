package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/ekzhu/lshensemble"
	"log"
	"os"
	"sort"
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

	const maxCapacity = 1000000 // your required line length
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
	inputFilePath := os.Args[1]
	var outputFilepath = os.Args[2]
	var keys, domains = readLinebyLine(inputFilePath)
	var keyToIndexMap = make(map[string]int)
	for i := range keys {
		keyToIndexMap[keys[i]] = i
		//fmt.Println(keys[i], domains[i])
	}

	// initializing the domain records to hold the MinHash signatures
	domainRecords := make([]*lshensemble.DomainRecord, len(domains))

	// set the minhash seed
	var seed int64 = 42

	// set the number of hash functions
	numHash := 256

	// create the domain records with the signatures
	for i := range domains {
		mh := lshensemble.NewMinhash(seed, numHash)
		for v := range domains[i] {
			mh.Push([]byte(v))
		}
		domainRecords[i] = &lshensemble.DomainRecord{
			Key:       keys[i],
			Size:      len(domains[i]),
			Signature: mh.Signature()}
	}
	sort.Sort(lshensemble.BySize(domainRecords))

	// Set the number of partitions
	numPart := 8

	// Set the maximum value for the MinHash LSH parameter K
	// (number of hash functions per band).
	maxK := 4

	fmt.Println("Building Index")
	// Create index using equi-depth partitioning
	// You can also use BootstrapLshEnsemblePlusEquiDepth for better accuracy
	index_eqd, err := lshensemble.BootstrapLshEnsembleEquiDepth(numPart, numHash, maxK,
		len(domainRecords), lshensemble.Recs2Chan(domainRecords))
	if err != nil {
		panic(err)
	}

	// Create index using optimal partitioning
	// You can also use BootstrapLshEnsemblePlusOptimal for better accuracy
	//index_opt, err := lshensemble.BootstrapLshEnsembleOptimal(numPart, numHash, maxK,
	//	func() <-chan *lshensemble.DomainRecord {
	//		return lshensemble.Recs2Chan(domainRecords)
	//	})
	//if err != nil {
	//	panic(err)
	//}

	fmt.Println("Beginning Querying")

	resultFile, err := os.Create(outputFilepath)
	if err != nil {
		log.Fatal(err)
	}
	resultFile.WriteString("id1,id2,compatibility\n")

	defer resultFile.Close()

	// pick a domain to use as the query
	fmt.Println("Found ", len(domainRecords), "domains to query - begin querying")
	var processed = 0
	for i := range domainRecords {
		if processed%1000 == 0 {
			fmt.Println("Processed", processed, "/", len(domainRecords), "(", 100.0*float64(processed)/float64(len(domainRecords)), "%)")
		}
		queryKey := keys[i]
		//fmt.Println("Querying ", queryKey)
		querySig := domainRecords[i].Signature
		querySize := domainRecords[i].Size

		// set the containment threshold
		threshold := 0.8

		// get the keys of the candidate domains (may contain false positives)
		// through a channel with option to cancel early.
		done := make(chan struct{})
		defer close(done) // Important!!
		results := index_eqd.Query(querySig, querySize, threshold, done)
		var queryDomain = domains[i]
		for key := range results {
			var keyAsString = key.(string)
			if queryKey < keyAsString {
				var keyIndex = keyToIndexMap[keyAsString]
				//compute actual overlap:
				var resultDomain = domains[keyIndex]
				var overlap = computeActualOverlap(queryDomain, resultDomain)
				if overlap >= threshold && key != queryKey {
					var line = queryKey + "," + keyAsString + "," + fmt.Sprintf("%f", overlap) + "\n"
					resultFile.WriteString(line)
				}
			}
		}
		processed++
	}
	fmt.Println("done")
	elapsed := time.Since(start)
	log.Printf("Application took %s", elapsed)
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
