# Decentralized Electronic Voting System using Linkable Ring Signatures

## Team members: 
Darshil Desai, 160020018 <br/>
Sucheta Ravikanti, 160040100

## Project Description:
This is a decentralized contract that when deployed can be used to perform electronic voting. Anyone can deploy this by giving the public keys of the vote bank as an argument migrations file. <br/> <br/>
Special features include: <br/> 
1. **Anonymity** and **authencity** of the voter is ensured. This is done by using **Ring Signatures**. 
2. **Double Voting** is also checked and such votes are dismissed. This is ensured by the use of a linkable (**I**) in the Ring Signatures. 
<!-- --> 
All these features have been tested and deployed here: <br/>
Etherscan Link (contract deployed on Ropsten): https://ropsten.etherscan.io/address/0xf30b7b4feaf2dcd8d334e0ba08cdeeffa48b2ef5
<br/> <br/>
References: 
1. https://kndrck.co/posts/introducing_heiswap/
2. https://github.com/kendricktan/heiswap-dapp
3. https://github.com/witnet/elliptic-curve-solidity
4. https://github.com/warner/python-ecdsa/blob/master/src/ecdsa/numbertheory.py


