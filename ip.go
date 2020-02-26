package main

import (
	"bytes"
	"net"
	"sort"
	"sync"
)

type ipRange struct {
	value string
	min   net.IP
	max   net.IP
}

func (i *ipRange) init() {
	ip, inet, _ := net.ParseCIDR(i.value)
	if len(inet.Mask) == net.IPv4len {
		ip = ip.To4()
	}

	min := ip.To4()
	if min == nil {
		min = ip.To16()
	}

	max := make([]byte, len(inet.Mask))
	for i := range inet.Mask {
		max[i] = ip[i] | ^inet.Mask[i]
	}

	i.min = min
	i.max = max
}

type chinaIPRangeDB struct {
	sync.RWMutex
	db []*ipRange
}

func (db *chinaIPRangeDB) Len() int {
	return len(db.db)
}

func (db *chinaIPRangeDB) Less(i, j int) bool {
	return bytes.Compare(db.db[i].max, db.db[j].min) == -1
}

func (db *chinaIPRangeDB) Swap(i, j int) {
	db.db[i], db.db[j] = db.db[j], db.db[i]
}

func (db *chinaIPRangeDB) contains(target net.IP) bool {
	if target == nil {
		return false
	}

	n := target.To4()
	if n == nil {
		n = target.To16()
	}
	target = n

	i := sort.Search(len(db.db), func(i int) bool {
		return bytes.Compare(target, db.db[i].min) == -1
	})

	i -= 1
	if i < 0 {
		return false
	}

	return bytes.Compare(target, db.db[i].min) >= 0 && bytes.Compare(target, db.db[i].max) <= 0
}

func newChinaIPRangeDB() *chinaIPRangeDB {
	for i := range db.db {
		db.db[i].init()
	}
	sort.Sort(db)
	return db
}
