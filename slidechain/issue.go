package main

// TODO(debnil): Use a more general-purpose sig checker, i.e. an exported `multisigProgCheckSrc`.
const issueProgFmt = `
	                                                    #  con stack                    arg stack                        log                                              notes
	                                                    #  ---------                    ---------                        ---                                              -----
	                                                    #                               asset code, amount, zeroval                                                       
	get get get                                         #  zeroval, amount, asset code                                                                                    
	[txid x"%x" get 0 checksig verify] contract put  #                               sigcheck contract                                                                 
	issue put                                           #                               sigcheck contract, issued value  {"A", vm.caller, v.amount, v.assetid, v.anchor}  
`

var (
	issueProgSrc string
	issueProg    []byte
	issueSeed    [32]byte
)
