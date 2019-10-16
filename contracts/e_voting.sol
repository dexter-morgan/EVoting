pragma solidity >=0.4.0 <0.6.0;
pragma experimental ABIEncoderV2;
import "./LSAG.sol";

contract EVoting {

    struct Voter {
        uint weight;
        bool voted;
        uint8 vote;
        address delegate;
    }

    struct Proposal {
        uint voteCount;
    }
    
    struct keyImages {
        uint256 x;
        uint256 y;
    }

    address chairperson;
    mapping(address => Voter) voters;
    Proposal[] proposals;
    uint256[2][] pub_keys;
    keyImages[] I_array;
    address common;

    constructor(uint256[2][] memory _pubkeys) public {
        chairperson = msg.sender;
        voters[chairperson].weight = 1;
        proposals.length = 3; 
        pub_keys = _pubkeys;
    }
    
    function setCommon(address _common) public {
        require(msg.sender == chairperson, "sender is not the chairperson. cant set the common address");
        common = _common;
    }

    function bytesToUint(bytes memory b) internal returns (uint256){
        uint256 number;
        for(uint i=0;i<b.length;i++){
            number = number + uint8(b[i])*(2**(8*(b.length-(i+1))));
        }
        return number;
    }
    
    function LSAG_verify(bytes memory message, uint256 c0, uint256[2] memory keyImage, uint256[] memory s, uint256[2][] memory publicKeys) internal returns (bool) {
        bool status = LSAG.verify(message, c0, keyImage, s, publicKeys);
        return status;
        
        if (!status) return false;
        for(uint i=0; i<I_array.length; i++) {
            if (keyImage[0] == I_array[i].x && keyImage[1] == I_array[i].y) return false;
        }
        keyImages memory new_keyimage;
        new_keyimage.x = keyImage[0];
        new_keyimage.y = keyImage[1];
        I_array.push(new_keyimage);
        return true;

    }
    
    /// Give a single vote to proposal $(toProposal).
    function vote(uint message, uint256 c0, uint256[2] memory keyImage, uint256[] memory s) public returns (bool){
        bytes memory message = toBytes(message);
        // require(msg.sender == common, "sender is not the common address");

        // require(LSAG_verify(message, c0, keyImage, s, pub_keys), "lsag verification didn't work"); 

        if ((msg.sender == common) && LSAG_verify(message, c0, keyImage, s, pub_keys)) {
            proposals[bytesToUint(message)-1].voteCount++;
            return true;
        }

        return false;
        
        // return proposals[bytesToUint(message)-1].voteCount;
    }

    function winningProposal() public view returns (uint8 _winningProposal, uint256 winningVoteCount) {
        uint256 winningVoteCount = 0;
        for (uint8 prop = 0; prop < proposals.length; prop++)
            if (proposals[prop].voteCount > winningVoteCount) {
                winningVoteCount = proposals[prop].voteCount;
                _winningProposal = prop;
            }
    }

    // function to convert uint to bytes
    function toBytes(uint256 x) public returns (bytes memory b) {
    b = new bytes(32);
    assembly { mstore(add(b, 32), x) }
}

}
