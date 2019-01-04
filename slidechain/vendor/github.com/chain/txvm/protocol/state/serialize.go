package state

import (
	"github.com/golang/protobuf/proto"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/patricia"
)

func (s *Snapshot) FromBytes(b []byte) error {
	var rs RawSnapshot
	err := proto.Unmarshal(b, &rs)
	if err != nil {
		return errors.Wrap(err, "unmarshaling state snapshot proto")
	}
	s.ContractsTree, err = treeFromBytes(rs.ContractNodes)
	if err != nil {
		return errors.Wrap(err, "reconstructing contracts tree")
	}
	s.NonceTree, err = treeFromBytes(rs.NonceNodes)
	if err != nil {
		return errors.Wrap(err, "reconstructing nonce tree")
	}
	if rs.Header != nil {
		s.Header = rs.Header
	}
	if rs.InitialBlockId != nil {
		s.InitialBlockID = *rs.InitialBlockId
	}
	for _, id := range rs.RefIds {
		s.RefIDs = append(s.RefIDs, *id)
	}
	return nil
}

func (s *Snapshot) Bytes() ([]byte, error) {
	rs := RawSnapshot{
		ContractNodes: treeToBytes(s.ContractsTree),
		NonceNodes:    treeToBytes(s.NonceTree),
	}
	if s.Header != nil {
		rs.Header = s.Header
	}
	if !s.InitialBlockID.IsZero() {
		rs.InitialBlockId = &s.InitialBlockID
	}
	b, err := proto.Marshal(&rs)
	return b, errors.Wrap(err, "marshaling state snapshot")
}

func treeToBytes(tree *patricia.Tree) [][]byte {
	var nodes [][]byte
	patricia.Walk(tree, func(item []byte) error {
		nodes = append(nodes, item)
		return nil
	})
	return nodes
}

func treeFromBytes(keys [][]byte) (*patricia.Tree, error) {
	tree := new(patricia.Tree)
	for _, k := range keys {
		err := tree.Insert(k)
		if err != nil {
			return nil, err
		}
	}
	return tree, nil
}
