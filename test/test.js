var EVoting = artifacts.require("EVoting");
const truffleAssert = require('truffle-assertions');

var contractInstance;
var voteCount;

contract("EVoting", async function(accounts){
    before(async () => {
        contractInstance = await EVoting.deployed();
    })
    describe("success states", async () => {
        
        it("Should add vote for proposal 1 when given a valid signature", async () => {
            var message = 1;
            var c0 = '0x41541AFB0800B2275136E073EFE69C4BFCCD2FF179BA64C0DC2AB62C1ED78F2C';
            var keyImage = ['0x5e6681f5b78337da2977b1de9e4bb6eb81d2267f730afbd81a34a7d41eac534', '0xc2be07ed3c8514c6ac1c806c7e1c64d3df8058c7880afd19a5713a0cfdb2c9f4'];
            var s = ['0x5585ba656512b5e3d3de3360f048b8d8d47dc06192fb5344c8d99553800e9442','0xec0f4cf49a62a2e2eb913779912a711067d3e840d1e21f5e9afc52785829933a','0x5598b2cb82cbfc0141fe22d6ad74ca6eeac8718a21a57a2bacad2d333a3d5cb2','0x18c6277f595e8218cd88cd5ee6c394bd457737fd33284229f6c5ea7902c3a93c','0x5a5318b559d21ab3d1ac0001e4e0075c94a7aa5eeb0500d1ecc62ceee25cbefe'];
            receipt = await contractInstance.setCommon(accounts[0], {from:accounts[0]});
            // console.log("receipt for setting common address : \n", receipt);
            voteCount = await contractInstance.vote.call((message), '0x61d6e58ace24edf0757654f8c210a0f8642548fad4f1c909999d2e8a77a5af57', keyImage, s, {from: accounts[0], gas:80000000});
    
            // assert.equal(voteCount, 1);

            return_values = await contractInstance.winningProposal.call({from: accounts[0], gas:8000000});

            assert(return_values[0], 1);
            assert(return_values[1], 1);
    
        
        });


        it("Should not double vote", async () => {
            var message = 1;
            var c0 = '0x41541AFB0800B2275136E073EFE69C4BFCCD2FF179BA64C0DC2AB62C1ED78F2C';
            var keyImage = ['0x5e6681f5b78337da2977b1de9e4bb6eb81d2267f730afbd81a34a7d41eac534', '0xc2be07ed3c8514c6ac1c806c7e1c64d3df8058c7880afd19a5713a0cfdb2c9f4'];
            var s = ['0x5585ba656512b5e3d3de3360f048b8d8d47dc06192fb5344c8d99553800e9442','0xec0f4cf49a62a2e2eb913779912a711067d3e840d1e21f5e9afc52785829933a','0x5598b2cb82cbfc0141fe22d6ad74ca6eeac8718a21a57a2bacad2d333a3d5cb2','0x18c6277f595e8218cd88cd5ee6c394bd457737fd33284229f6c5ea7902c3a93c','0x5a5318b559d21ab3d1ac0001e4e0075c94a7aa5eeb0500d1ecc62ceee25cbefe'];
            receipt = await contractInstance.setCommon(accounts[0], {from:accounts[0]});
            // console.log("Receipt for setting common address : \n", receipt);
            voteCount = await contractInstance.vote.call((message), '0x61d6e58ace24edf0757654f8c210a0f8642548fad4f1c909999d2e8a77a5af57', keyImage, s, {from: accounts[0], gas:80000000000});

            voteCount = await contractInstance.vote.call((message), '0x61d6e58ace24edf0757654f8c210a0f8642548fad4f1c909999d2e8a77a5af57', keyImage, s, {from: accounts[0], gas:80000000000});

            return_values = await contractInstance.winningProposal.call({from: accounts[0], gas:8000000});

            assert(return_values[0], 1);
            assert(return_values[1], 1);
    
        
        });

        it("Should not allow users with invalid signatures vote", async () => {
            var message = 1;
            var c0 = '0x41541AFB0800B2275136E073EFE69C4BFCCD2FF179BA64C0DC2AB62C1ED78F2C';
            var keyImage = ['0x5e6681f5b78337da2977b1de9e4bb6eb81d2267f730afbd81a34a7d41eac534', '0xc2be07ed3c8514c6ac1c806c7e1c64d3df8058c7880afd19a5713a0cfdb2c9f4'];
            var s = ['0x5585ba656512b5e3d3de3360f048b8d8d47dc06192fb5344c8d99553800e9442','0xec0f4cf49a62a2e2eb913779912a711067d3e840d1e21f5e9afc52785829933a','0x5598b2cb82cbfc0141fe22d6ad74ca6eeac8718a21a57a2bacad2d333a3d5cb2','0x18c6277f595e8218cd88cd5ee6c394bd457737fd33284229f6c5ea7902c3a93c','0x5a5318b559d21ab3d1ac0001e4e0075c94a7aa5eeb0500d1ecc62ceee25cbefe'];

            receipt = await contractInstance.setCommon(accounts[0], {from:accounts[0]});
            // console.log("Receipt for setting common address : \n", receipt);
            voteCount = await contractInstance.vote.call((message), '0x61d6e58ace24edf0757654f8c210a0f8642548fad4f1c909999d2e8a77a5af57', keyImage, s, {from: accounts[0], gas:80000000000});

            var message = 1;
            var c0 = '0x41541AFB0800B2275136E073EFE69C4BFCCD2FF179BA64C0DC2AB62C1ED78F2C';
            var keyImage = ['0x5e6681f5b78337da2977b1de9e4bb6eb81d2267f730afbd81a34a7d41eac534', '0xc2be07ed3c8514c6ac1c806c7e1c64d3df8058c7880afd19a5713a0cfdb2c9f4'];
            var s = ['0x5585ba656512b5e3d3de3360f048b8d8d47dc06192fb5344c8d99553800e9442','0xac0f4cf49a62a2e2eb913779912a711067d3e840d1e21f5e9afc52785829933a','0x5598b2cb82cbfc0141fe22d6ad74ca6eeac8718a21a57a2bacad2d333a3d5cb2','0x18c6277f595e8218cd88cd5ee6c394bd457737fd33284229f6c5ea7902c3a93c','0x5a5318b559d21ab3d1ac0001e4e0075c94a7aa5eeb0500d1ecc62ceee25cbefe'];

            voteCount = await contractInstance.vote.call((message), '0x61d6e58ace24edf0757654f8c210a0f8642548fad4f1c909999d2e8a77a5af57', keyImage, s, {from: accounts[0], gas:80000000000});
    
            // assert.equal(voteCount, 1);

            return_values = await contractInstance.winningProposal.call({from: accounts[0], gas:8000000});

            assert(return_values[0], 1);
            assert(return_values[1], 1);
    
        
        });
    })
})
    