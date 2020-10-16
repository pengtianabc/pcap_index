# pcap_index

## TODO 
### for search a flow
Add `reverse` bit index to normalize `src`/`dst` field for a flow, assume the variabe bitmap is `reverse`

  a simple icmp flow with 2 pkt is:
  
(1) `sip=>dip`

(2) `sip<=sip`

save it to:

(1) `s=sip, d=dip, reverse=0`

(2) `s=sip, d=dip, reverse=0`

  - if we search the first a packet, expression is `s=sip, d=dip, reverse=0`, will find the fist packet
  
  - if web search the whole flow, expresssion is (`s=sip, d=sip, reverse=0`) || (`s=sip, d=sip, reverse=1`), equal as: `s=sip, d=dip`, so we cant find the whole flow, instead use (`sip=sip, d=dip`) or (`s=dip, d=sip`)
 
  - `reverse` is very important, the program should keep it correct, otherwise, the search condition is inversed 
