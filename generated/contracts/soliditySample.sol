pragma solidity ^0.8.4;

contract ECRecovery {

    /**
    * @dev Recover signer address from a message by using their signature
    * @param hash bytes32 message, the hash is the signed message. What is recovered is the signer address.
    * @param sig bytes signature, the signature is generated using web3.eth.sign()
    */
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        //Check the signature length
        if (sig.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            return ecrecover(hash, v, r, s);
        }
    }
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);


    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}


contract MattAuction is ECRecovery {
    uint256 _chain_id;
            
    constructor( uint chainId) { 
        _chain_id = chainId;
    }       

    struct Bid { 
        uint256 nft;
        address bidderAddress;
        address currencyTokenAddress;
        uint256 currencyTokenAmount;
    }

    struct SignedBid {
        Bid bid;
        bytes sig;
    }

    struct Auction {
        uint endTime;
        address owner;
        address currencyTokenAddress;
        bool open;
    }

    mapping (bytes32 => Auction) auctions;

    function startAuction (bytes32 nftData, uint endTime, address token, address owner) public {
       auctions[nftData] = Auction(endTime, owner, token, true);
    }

    function endAuction (bytes32 nftData, SignedBid[] calldata signedBids) public {
        Auction memory auction = auctions[nftData];

        // Enforce only the auction owner can end it
        assert(msg.sender == auction.owner);

        // Assume the lowest (price-setting) bid is first (enforce in the loop)
        uint256 price = signedBids[0].bid.currencyTokenAmount;

        for (uint i=0; i < signedBids.length; i++) {
            SignedBid memory signed = signedBids[i];

            // Enforce all bids are above or equal to the first (low) bid price:
            assert(signed.bid.currencyTokenAmount >= price);

            // Ensure the bid meant to be in the auction's currency.
            // This data was redundant to sign, but improves end-user legibility.
            assert(signed.bid.currencyTokenAddress == auction.currencyTokenAddress);

            // Verify signature
            assert(verifyBidSignature(signed.bid.nft, signed.bid.bidderAddress, signed.bid.currencyTokenAddress, signed.bid.currencyTokenAmount, signed.sig));

            // Transfer payment
            IERC20(auction.currencyTokenAddress).transferFrom(signed.bid.currencyTokenAddress, auction.owner, price);

            // TODO: Issue NFT
        }        

        auction.open = false;
        auctions[nftData] = auction;
    }
    
    bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string contractName,string version,uint256 chainId,address verifyingContract)"
    );

    function getDomainTypehash() public pure returns (bytes32) {
        return EIP712DOMAIN_TYPEHASH;
    }

    function getEIP712DomainHash(string memory contractName, string memory version, uint256 chainId, address verifyingContract) public pure returns (bytes32) {
        return keccak256(abi.encode(
            EIP712DOMAIN_TYPEHASH,
            keccak256(bytes(contractName)),
            keccak256(bytes(version)),
            chainId,
            verifyingContract
        ));
    }

    bytes32 constant PACKET_TYPEHASH = keccak256(
    "Bid(uint256 nft,address bidderAddress,address currencyTokenAddress,uint256 currencyTokenAmount)"
    );
        
    function getPacketTypehash()  public pure returns (bytes32) {
        return PACKET_TYPEHASH;
    }

    function getPacketHash(uint256 nft,address bidderAddress,address currencyTokenAddress,uint256 currencyTokenAmount) public pure returns (bytes32) {
        return keccak256(abi.encode(
            PACKET_TYPEHASH,
            nft,
            bidderAddress,
            currencyTokenAddress,
            currencyTokenAmount
        ));
    }

    function getTypedDataHash(uint256 nft,address bidderAddress,address currencyTokenAddress,uint256 currencyTokenAmount) public view returns (bytes32) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            getEIP712DomainHash('MattAuction','1',_chain_id,address(this)),
            getPacketHash(nft,bidderAddress,currencyTokenAddress,currencyTokenAmount)
        ));
        return digest;
    }

    function verifyBidSignature(uint256 nft,address bidderAddress,address currencyTokenAddress,uint256 currencyTokenAmount,bytes memory offchainSignature) public view returns (bool) {
        bytes32 sigHash = getTypedDataHash(nft,bidderAddress,currencyTokenAddress,currencyTokenAmount);
        address recoveredSignatureSigner = recover(sigHash,offchainSignature);
        require(bidderAddress == recoveredSignatureSigner, 'Invalid signature');
        //DO SOME FUN STUFF HERE
        return true;
    }

}