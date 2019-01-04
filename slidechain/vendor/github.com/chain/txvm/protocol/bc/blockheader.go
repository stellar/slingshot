package bc

import (
	"database/sql/driver"

	"github.com/golang/protobuf/proto"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm"
)

// Hash computes the unique Chain protocol hash of the BlockHeader.
func (bh *BlockHeader) Hash() (hash Hash) {
	emptyHash := make([]byte, 32)
	prevID, txRoot, contractRoot, nonceRoot := emptyHash, emptyHash, emptyHash, emptyHash
	if bh.PreviousBlockId != nil {
		prevID = bh.PreviousBlockId.Bytes()
	}
	if bh.TransactionsRoot != nil {
		txRoot = bh.TransactionsRoot.Bytes()
	}
	if bh.ContractsRoot != nil {
		contractRoot = bh.ContractsRoot.Bytes()
	}
	if bh.NoncesRoot != nil {
		nonceRoot = bh.NoncesRoot.Bytes()
	}

	predicateTuple := txvm.Tuple{
		txvm.Int(bh.NextPredicate.Version),
	}
	if bh.NextPredicate.Version == 1 {
		predicateTuple = append(predicateTuple, txvm.Int(bh.NextPredicate.Quorum))
		for _, pk := range bh.NextPredicate.Pubkeys {
			predicateTuple = append(predicateTuple, txvm.Bytes(pk))
		}
	} else {
		for _, item := range bh.NextPredicate.OtherFields {
			predicateTuple = append(predicateTuple, item.asTxvm())
		}
	}

	tupleHeader := txvm.Tuple{
		txvm.Int(bh.Version),
		txvm.Int(bh.Height),
		txvm.Bytes(prevID),
		txvm.Int(bh.TimestampMs),
		txvm.Int(bh.RefsCount),
		txvm.Int(bh.Runlimit),
		txvm.Bytes(txRoot),
		txvm.Bytes(contractRoot),
		txvm.Bytes(nonceRoot),
		predicateTuple,
	}
	for _, item := range bh.ExtraFields {
		tupleHeader = append(tupleHeader, item.asTxvm())
	}

	return NewHash(txvm.VMHash("BlockID", txvm.Encode(tupleHeader)))
}

// Scan satisfies the database.sql.Scanner interface.
func (bh *BlockHeader) Scan(val interface{}) error {
	driverBuf, ok := val.([]byte)
	if !ok {
		return errors.New("Scan must receive a byte slice")
	}
	buf := make([]byte, len(driverBuf))
	copy(buf, driverBuf)
	return proto.Unmarshal(buf, bh)
}

// Value satisfies the Valuer interface from database/sql/driver.
func (bh *BlockHeader) Value() (driver.Value, error) {
	return proto.Marshal(bh)
}

func (item *DataItem) asTxvm() txvm.Data {
	switch item.Type {
	case DataType_BYTES:
		return txvm.Bytes(item.Bytes)
	case DataType_INT:
		return txvm.Int(item.Int)
	case DataType_TUPLE:
		var result txvm.Tuple
		for _, elt := range item.Tuple {
			result = append(result, elt.asTxvm())
		}
		return result
	}
	return nil // should be impossible
}
