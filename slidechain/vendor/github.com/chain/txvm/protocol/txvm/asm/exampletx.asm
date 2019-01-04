[x'' put {x'70a50f2cc703e8a6fcbbae4487904091655d4d5b7e40fa521f96d380f6a7bf5f'} put 1 put x'' put 100 put x'e3ea8f91ef6a6c75f6bc2b31eda1fdded7e58fce2665dba060947d305f57b6b8' put x'0e9eb1d57434b15f' put 1520642465675 put [
                  # Contract stack                                          Argument stack                                                        Log
                  # []                                                      [refdata pubkeys quorum tag amount (zeroval 0)|(blockid nonce maxms)]
get               # [(0|maxms)]                                             [refdata pubkeys quorum tag amount (zeroval|blockid nonce)]
dup not           # [(0|maxms) ((0|maxms)==0)]                              [refdata pubkeys quorum tag amount (zeroval|blockid nonce)]
jumpif:$havezero  # [maxms]                                                 [refdata pubkeys quorum tag amount blockid nonce]
    get drop      # [maxms]                                                 [refdata pubkeys quorum tag amount blockid]
    get           # [maxms blockid]                                         [refdata pubkeys quorum tag amount]
    swap          # [blockid maxms]                                         [refdata pubkeys quorum tag amount]
    nonce         # [zeroval]                                               [refdata pubkeys quorum tag amount]                                   [{"N", <caller>, <cseed>, bid, exp} {"R", minms, maxms}]
    jump:$cont
$havezero         # [0]                                                     [refdata pubkeys quorum tag amount zeroval]                           []
drop get          # [zeroval]                                               [refdata pubkeys quorum tag amount]                                   []
$cont
get               # [zeroval amount]                                        [refdata pubkeys quorum tag]                                          [({"N", ...} {"R", ...})]
get               # [zeroval amount tag]                                    [refdata pubkeys quorum]                                              [({"N", ...} {"R", ...})]
get               # [zeroval amount tag quorum]                             [refdata pubkeys]                                                     [({"N", ...} {"R", ...})]
dup 4 bury        # [quorum zeroval amount tag quorum]                      [refdata pubkeys]                                                     [({"N", ...} {"R", ...})]
get               # [quorum zeroval amount tag quorum pubkeys]              [refdata]                                                             [({"N", ...} {"R", ...})]
dup 5 bury        # [quorum pubkeys zeroval amount tag quorum pubkeys]      []                                                                    [({"N", ...} {"R", ...})]
3 tuple           # [quorum pubkeys zeroval amount {tag, quorum, pubkeys}]  []                                                                    [({"N", ...} {"R", ...})]
encode            # [quorum pubkeys zeroval amount tag']                    []                                                                    [({"N", ...} {"R", ...})]
issue             # [quorum pubkeys issuedval]                              [refdata]                                                             [({"N", ...} {"R", ...}) {"A", <caller>, amount, assetID, zeroval.anchor}]
get log           # [quorum pubkeys issuedval]                              []                                                                    [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
anchor            # [quorum pubkeys issuedval anchor]                       []                                                                    [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
swap put          # [quorum pubkeys anchor]                                 [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]              # [quorum pubkeys anchor <multisigprog>]                  [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
yield             # [quorum pubkeys anchor]                                 [issuedval]                                                           [({"N", ...} {"R", ...}) {"A", ...} {"L", <cseed>, refdata}]
] contract call] contract call
get get
0 split
x'' put
x'' put
1 roll
put
{x'd0dcf2615bfb9aaa4f5c2722f4f9592488490ebc0096b3ee3dbb9e85ac831557'} put
1 put
[
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
] contract call
x'' put
		{'C', x'47bb956c9e8844bf5d3cc3ed93d01e275353523142b6fb3999b5d0e11a958ffa', [
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
],
			{'Z', 1},                # {'Z', quorum}
			{'T', {x'd0dcf2615bfb9aaa4f5c2722f4f9592488490ebc0096b3ee3dbb9e85ac831557'}},              # {'T', {p1,...,p_n}}
			{'V', 100, x'12a13844b3cd7c9fc9897da87defefe368286925c626d523f5d8df295ff879dc', x'42d4b866a3f6b81f6501bb9b9e6d5e411eefac27859a52bbfb581e17a21f600e'}   # {'V', amount, assetID, anchor}
		} input call

get get
x'' put
x'' put
75 split
put
{x'4e0984c7e108cc6a195dd8788b08cbe5a452204ceac409843395338c6c6b7f7e'} put
1 put
[
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
] contract call
x'' put
x'' put
put
{x'58414c5d18cc783796fade0dc4cce9cb7ded4d7c0e50281a525a7706418c6296'} put
1 put
[
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
] contract call
x'' put
		{'C', x'47bb956c9e8844bf5d3cc3ed93d01e275353523142b6fb3999b5d0e11a958ffa', [
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
],
			{'Z', 1},                # {'Z', quorum}
			{'T', {x'4e0984c7e108cc6a195dd8788b08cbe5a452204ceac409843395338c6c6b7f7e'}},              # {'T', {p1,...,p_n}}
			{'V', 75, x'12a13844b3cd7c9fc9897da87defefe368286925c626d523f5d8df295ff879dc', x'7c0fb9607265c46ffc730234640bbff1ab01689e0a43772cccebe8cebaaf3ab9'}   # {'V', amount, assetID, anchor}
		} input call

get get
x'' put
x'' put
50 split
put
{x'01d482d0f52b3605e67d09e5149493a9572c1b05d45de13bc4c3737a20fa399b'} put
1 put
[
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
] contract call
x'' put
x'' put
put
{x'7dec555a67565a6e33ded2a4516616aa73f2694aa844a4d78ac3f8dd6d6f1129'} put
1 put
[
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
] contract call
x'' put
		{'C', x'47bb956c9e8844bf5d3cc3ed93d01e275353523142b6fb3999b5d0e11a958ffa', [
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
],
			{'Z', 1},                # {'Z', quorum}
			{'T', {x'01d482d0f52b3605e67d09e5149493a9572c1b05d45de13bc4c3737a20fa399b'}},              # {'T', {p1,...,p_n}}
			{'V', 50, x'12a13844b3cd7c9fc9897da87defefe368286925c626d523f5d8df295ff879dc', x'bc3b2f673700b045cdaa0a0b6f51772ff7699f077d14ba824038c17009b95a9e'}   # {'V', amount, assetID, anchor}
		} input call

get get
x'' put
x'' put
25 split
put
{x'f83bbe8aef7364111005be903aebc2fb55e01f1e97b279bed9bafd60bc80886d'} put
1 put
[
	               # Contract stack                         Argument stack                   Log
	               # []                                     [refdata tags v {p1,...,p_n} q]  []
	get get        # [q {p1,...,p_n}]                       [refdata tags v]                 []
	get            # [q {p1,...,p_n} v]                     [refdata tags]                   []
	get log        # [q {p1,...,p_n} v]                     [refdata]                        [{"L", <cid>, tags}]
	get log        # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	[
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[
	                    # Contract stack                                                Argument stack
	                    # [quorum {p1,...,p_n} anchor]                                  [s1 ... s_n prog]
	swap untuple        # [quorum anchor p1 ... p_n n]                                  [s1 ... s_n prog]
	get                 # [quorum anchor p1 ... p_n n prog]                             [s1 ... s_n]
	dup                 # [quorum anchor p1 ... p_n n prog prog]                        [s1 ... s_n]
	2 peek              # [quorum anchor p1 ... p_n n prog prog n]                      [s1 ... s_n]
	3 add               # [quorum anchor p1 ... p_n n prog prog (n+3)]                  [s1 ... s_n]
	roll                # [quorum p1 ... p_n   n prog prog anchor]                      [s1 ... s_n]
	cat                 # [quorum p1 ... p_n   n prog proganchor]                       [s1 ... s_n]
	0                   # [quorum p1 ... p_n   n prog proganchor 0]                     [s1 ... s_n]
	3 roll              # [quorum p1 ... p_n   prog proganchor 0 n]                     [s1 ... s_n]
	$sigstart           # [quorum p1 ... p_n   prog proganchor t n],  t = 0..n          [s1 ... s_n]
	    dup 0 eq        # [quorum p1 ... p_n   prog proganchor t n (n==0)]              [s1 ... s_n]
	    jumpif:$sigend  # [quorum p1 ... p_n   prog proganchor t n]                     [s1 ... s_n]
	    2 peek          # [quorum p1 ... p_n   prog proganchor t n proganchor]          [s1 ... s_n]
	    5 roll          # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n]      [s1 ... s_n]
	    get             # [quorum p1 ... p_n-1 prog proganchor t n proganchor p_n s_n]  [s1 ... s_n-1]
	    0 checksig      # [quorum p1 ... p_n-1 prog proganchor t n bool]                [s1 ... s_n-1]
	    2 roll add      # [quorum p1 ... p_n-1 prog proganchor n t’]                    [s1 ... s_n-1]
	    swap            # [quorum p1 ... p_n-1 prog proganchor t’ n]                    [s1 ... s_n-1]
	    1 sub           # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	    jump:$sigstart  # [quorum p1 ... p_n-1 prog proganchor t’ (n-1)]                [s1 ... s_n-1]
	$sigend             # [quorum prog proganchor t 0]                                  []
	drop                # [quorum prog proganchor t]                                    []
	3 roll              # [prog proganchor t quorum]                                    []
	eq verify           # [prog proganchor]                                             []
	drop exec
]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
]           # [q {p1,...,p_n} v <msunlock>]          []                               [{"L", <cid>, tags} {"L", <cid>, refdata}]
	output         # [q {p1,...,p_n} v]                     []                               [{"L", <cid>, tags} {"L", <cid>, refdata} {"O", <caller>, <outputid>}]
] contract call
x'' put
put
[
	            # Contract stack   Argument stack   Log
	            # []               [refdata value]  []
	get retire  # []               [refdata]        [{"X", <cid>, amount, assetID, anchor}]
	get log     # []               []               [{"X", <cid>, amount, assetID, anchor} {"L", <cid>, refdata}]
] contract call
1520642165680 1520642465675 timerange
x'' log
3 roll
finalize
'' put
[txid x'5a14352b411cfb2591201c99897e6167f2daacc3365336ecf0f338580889f12d' eq verify] put
call
'' put
[txid x'5a14352b411cfb2591201c99897e6167f2daacc3365336ecf0f338580889f12d' eq verify] put
call
'' put
[txid x'5a14352b411cfb2591201c99897e6167f2daacc3365336ecf0f338580889f12d' eq verify] put
call
'' put
[txid x'5a14352b411cfb2591201c99897e6167f2daacc3365336ecf0f338580889f12d' eq verify] put
call
