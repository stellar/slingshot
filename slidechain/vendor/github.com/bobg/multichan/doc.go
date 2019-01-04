// Package multichan provides a one-to-many data channel.
//
// The source of some data creates a writer (type multichan.W)
// and supplies items to it one at a time with W.Write.
//
// Consumers of those items create readers with W.Reader
// (producing a multichan.R)
// and read items with R.Read and R.NBRead.
package multichan
