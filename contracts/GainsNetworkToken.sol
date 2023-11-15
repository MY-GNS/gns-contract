// File: node_modules\@openzeppelin\contracts\utils\Context.sol

// SPDX-License-Identifier: MIT
import "@openzeppelin/contracts/utils/Context.sol";

// File: node_modules\@openzeppelin\contracts\token\ERC20\IERC20.sol
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// File: node_modules\@openzeppelin\contracts\token\ERC20\ERC20.sol
import  "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// File: @openzeppelin\contracts\token\ERC20\ERC20Capped.sol
import  "@openzeppelin/contracts/token/ERC20/ERC20Capped.sol";


// File: node_modules\@openzeppelin\contracts\utils\EnumerableSet.sol
import "@openzeppelin/contracts/utils/EnumerableSet.sol";

// File: node_modules\@openzeppelin\contracts\utils\Address.sol
import  "@openzeppelin/contracts/utils/Address.sol";


// File: @openzeppelin\contracts\access\AccessControl.sol
import  "@openzeppelin/contracts/access/AccessControl.sol";

// File: contracts\polygon\common\AccessControlMixin.sol

contract AccessControlMixin is AccessControl {
    string private _revertMsg;
    function _setupContractId(string memory contractId) internal {
        _revertMsg = string(abi.encodePacked(contractId, ": INSUFFICIENT_PERMISSIONS"));
    }

    modifier only(bytes32 role) {
        require(
            hasRole(role, _msgSender()),
            _revertMsg
        );
        _;
    }
}

// File: contracts\polygon\child\ChildToken\IChildToken.sol

pragma solidity 0.6.6;

interface IChildToken {
    function deposit(address user, bytes calldata depositData) external;
}

// File: contracts\polygon\common\Initializable.sol

pragma solidity 0.6.6;

contract Initializable {
    bool inited = false;

    modifier initializer() {
        require(!inited, "already inited");
        _;
        inited = true;
    }
}

// File: contracts\polygon\common\EIP712Base.sol

pragma solidity 0.6.6;


contract EIP712Base is Initializable {
    struct EIP712Domain {
        string name;
        string version;
        address verifyingContract;
        bytes32 salt;
    }

    string constant public ERC712_VERSION = "1";

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        bytes(
            "EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)"
        )
    );
    bytes32 internal domainSeperator;

    // supposed to be called once while initializing.
    // one of the contractsa that inherits this contract follows proxy pattern
    // so it is not possible to do this in a constructor
    function _initializeEIP712(
        string memory name
    )
        internal
        initializer
    {
        _setDomainSeperator(name);
    }

    function _setDomainSeperator(string memory name) internal {
        domainSeperator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(ERC712_VERSION)),
                address(this),
                bytes32(getChainId())
            )
        );
    }

    function getDomainSeperator() public view returns (bytes32) {
        return domainSeperator;
    }

    function getChainId() public pure returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * Accept message hash and returns hash message in EIP712 compatible form
     * So that it can be used to recover signer from signature signed using EIP712 formatted data
     * https://eips.ethereum.org/EIPS/eip-712
     * "\\x19" makes the encoding deterministic
     * "\\x01" is the version byte to make it compatible to EIP-191
     */
    function toTypedMessageHash(bytes32 messageHash)
        internal
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19\x01", getDomainSeperator(), messageHash)
            );
    }
}

// File: contracts\polygon\common\NativeMetaTransaction.sol

pragma solidity 0.6.6;



contract NativeMetaTransaction is EIP712Base {
    using SafeMath for uint256;
    bytes32 private constant META_TRANSACTION_TYPEHASH = keccak256(
        bytes(
            "MetaTransaction(uint256 nonce,address from,bytes functionSignature)"
        )
    );
    event MetaTransactionExecuted(
        address userAddress,
        address payable relayerAddress,
        bytes functionSignature
    );
    mapping(address => uint256) nonces;

    /*
     * Meta transaction structure.
     * No point of including value field here as if user is doing value transfer then he has the funds to pay for gas
     * He should call the desired function directly in that case.
     */
    struct MetaTransaction {
        uint256 nonce;
        address from;
        bytes functionSignature;
    }

    function executeMetaTransaction(
        address userAddress,
        bytes memory functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) public payable returns (bytes memory) {
        MetaTransaction memory metaTx = MetaTransaction({
            nonce: nonces[userAddress],
            from: userAddress,
            functionSignature: functionSignature
        });

        require(
            verify(userAddress, metaTx, sigR, sigS, sigV),
            "Signer and signature do not match"
        );

        // increase nonce for user (to avoid re-use)
        nonces[userAddress] = nonces[userAddress].add(1);

        emit MetaTransactionExecuted(
            userAddress,
            msg.sender,
            functionSignature
        );

        // Append userAddress and relayer address at the end to extract it from calling context
        (bool success, bytes memory returnData) = address(this).call(
            abi.encodePacked(functionSignature, userAddress)
        );
        require(success, "Function call not successful");

        return returnData;
    }

    function hashMetaTransaction(MetaTransaction memory metaTx)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    META_TRANSACTION_TYPEHASH,
                    metaTx.nonce,
                    metaTx.from,
                    keccak256(metaTx.functionSignature)
                )
            );
    }

    function getNonce(address user) public view returns (uint256 nonce) {
        nonce = nonces[user];
    }

    function verify(
        address signer,
        MetaTransaction memory metaTx,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) internal view returns (bool) {
        require(signer != address(0), "NativeMetaTransaction: INVALID_SIGNER");
        return
            signer ==
            ecrecover(
                toTypedMessageHash(hashMetaTransaction(metaTx)),
                sigV,
                sigR,
                sigS
            );
    }
}

// File: contracts\polygon\common\ContextMixin.sol

pragma solidity 0.6.6;

abstract contract ContextMixin {
    function msgSender()
        internal
        view
        returns (address payable sender)
    {
        if (msg.sender == address(this)) {
            bytes memory array = msg.data;
            uint256 index = msg.data.length;
            assembly {
                // Load the 32 bytes word from memory with the address on the lower 20 bytes, and mask those.
                sender := and(
                    mload(add(array, index)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
            }
        } else {
            sender = msg.sender;
        }
        return sender;
    }
}

// File: contracts\GainsNetworkToken.sol

pragma solidity 0.6.6;



contract GainsNetworkToken is
    ERC20Capped,
    IChildToken,
    AccessControlMixin,
    NativeMetaTransaction,
    ContextMixin
{
    bytes32 public constant DEPOSITOR_ROLE = keccak256("DEPOSITOR_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    struct GrantRequest {
        bytes32[] roles;
        uint initiated;
    }
    mapping(address => GrantRequest) grantRequests;
    uint constant public MIN_GRANT_REQUEST_DELAY = 45000; // 1 day

    event GrantRequestInitiated(bytes32[] indexed roles, address indexed account, uint indexed block);
    event GrantRequestCanceled(address indexed account, uint indexed canceled);

    constructor(
        address tradingStorage,
        address trading,
        address callbacks,
        address vault,
        address pool,
        address tokenMigration
    ) public ERC20Capped(100*(10**6)*(10**18)) ERC20("Gains Network", "GNS") {

        // Token init
        _setupContractId("ChildMintableERC20");
        _setupDecimals(18);
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(DEPOSITOR_ROLE, 0xA6FA4fB5f76172d178d61B04b0ecd319C5d1C0aa);
        _initializeEIP712("Gains Network");

        // Trading roles
        _setupRole(MINTER_ROLE, tradingStorage);
        _setupRole(BURNER_ROLE, tradingStorage);
        _setupRole(MINTER_ROLE, trading);
        _setupRole(MINTER_ROLE, callbacks);
        _setupRole(MINTER_ROLE, vault);
        _setupRole(MINTER_ROLE, pool);
        _setupRole(MINTER_ROLE, tokenMigration);
    }

    // This is to support Native meta transactions
    // never use msg.sender directly, use _msgSender() instead
    function _msgSender()
        internal
        override
        view
        returns (address payable sender)
    {
        return ContextMixin.msgSender();
    }

    // Disable grantRole AccessControl function (can only be done after timelock)
    function grantRole(bytes32 /*role*/, address /*account*/) public override {
        require(false, "DISABLED (TIMELOCK)");
    }

    // Returns true if a grant request was initiated for this account.
    function grantRequestInitiated(address account) public view returns(bool){
        GrantRequest memory r = grantRequests[account];
        return r.roles.length > 0 && r.initiated > 0;
    }

    // Initiates a request to grant `role` to `account` at current block number.
    function initiateGrantRequest(bytes32[] calldata roles, address account) external only(DEFAULT_ADMIN_ROLE){
        require(!grantRequestInitiated(account), "Grant request already initiated for this account.");
        grantRequests[account] = GrantRequest(roles, block.number);
        emit GrantRequestInitiated(roles, account, block.number);
    }

    // Cancels a request to grant `role` to `account`
    function cancelGrantRequest(address account) external only(DEFAULT_ADMIN_ROLE){
        require(grantRequestInitiated(account), "You must first initiate a grant request for this role and account.");
        delete grantRequests[account];
        emit GrantRequestCanceled(account, block.number);
    }

    // Grant the roles precised in the request to account (must wait for the timelock)
    function executeGrantRequest(address account) public only(DEFAULT_ADMIN_ROLE){
        require(grantRequestInitiated(account), "You must first initiate a grant request for this role and account.");

        GrantRequest memory r = grantRequests[account];
        require(block.number >= r.initiated + MIN_GRANT_REQUEST_DELAY, "You must wait for the minimum delay after initiating a request.");

        for(uint i = 0; i < r.roles.length; i++){
            _setupRole(r.roles[i], account);
        }

        delete grantRequests[account];
    }

    // Mint tokens (called by our ecosystem contracts)
    function mint(address to, uint amount) external only(MINTER_ROLE){
        _mint(to, amount);
    }

    // Burn tokens (called by our ecosystem contracts)
    function burn(address from, uint amount) external only(BURNER_ROLE){
        _burn(from, amount);
    }

    /**
     * @notice called when token is deposited on root chain
     * @dev Should be callable only by ChildChainManager
     * Should handle deposit by minting the required amount for user
     * Make sure minting is done only by this function
     * @param user user address for whom deposit is being done
     * @param depositData abi encoded amount
     */
    function deposit(address user, bytes calldata depositData)
        external
        override
        only(DEPOSITOR_ROLE)
    {
        uint256 amount = abi.decode(depositData, (uint256));
        _mint(user, amount);
    }

    /**
     * @notice called when user wants to withdraw tokens back to root chain
     * @dev Should burn user's tokens. This transaction will be verified when exiting on root chain
     * @param amount amount of tokens to withdraw
     */
    function withdraw(uint256 amount) external {
        _burn(_msgSender(), amount);
    }

}
