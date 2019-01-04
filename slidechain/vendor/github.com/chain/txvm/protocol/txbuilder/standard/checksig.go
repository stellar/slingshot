package standard

// multisigProgCheckSrc expects:
//   argument stack: [... s1 s2 ... s_n prog]
//   contract stack: [... quorum {p1, p2, ..., p_n} anchor]
// It checks that each `s_i` is a valid signature of
// the program string `prog`||`anchor` for a public key `p_i`.
// There must be exactly `quorum` such valid signatures;
// remaining signatures must be empty strings.
// If these checks pass, this program then execs `prog`.
//
// `prog` can be the one produced by `VerifyTxID`, for one.
const multisigProgCheckSrc = `
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
`
