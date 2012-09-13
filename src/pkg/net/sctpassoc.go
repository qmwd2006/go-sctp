package net

type SCTPAssoc struct {
   In chan []byte
}

func (conn *SCTPConn) ListenAssociation() (assoc *SCTPAssoc, err error) {

