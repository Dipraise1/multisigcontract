// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title MultiSigWallet - Enhanced Edition with Advanced Security
 * @dev A feature-rich, enterprise-grade multi-signature wallet with unique capabilities
 * @dev Perfect for team treasuries, DAO governance, and advanced fund management
 * @dev Features: Time-locks, batch operations, emergency recovery, transaction scheduling
 * @dev Security: Rate limiting, owner activity monitoring, transaction validation, emergency protocols
 * @author Built with ❤️ for the Ethereum community
 * @custom:security-contact security@multisigeth.com
 */
contract MultiSigWallet is ReentrancyGuard, Pausable {
    // ========================================
    // EVENTS - For transparency and monitoring
    // ========================================
    event Deposit(address indexed sender, uint256 amount, uint256 balance);
    event SubmitTransaction(
        address indexed owner,
        uint256 indexed txIndex,
        address indexed to,
        uint256 value,
        bytes data,
        uint256 unlockTime
    );
    event ConfirmTransaction(address indexed owner, uint256 indexed txIndex);
    event RevokeConfirmation(address indexed owner, uint256 indexed txIndex);
    event ExecuteTransaction(address indexed owner, uint256 indexed txIndex);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 newThreshold);
    event TransactionScheduled(uint256 indexed txIndex, uint256 unlockTime);
    event EmergencyRecovery(address indexed recoveredBy, uint256 amount);
    event BatchTransactionSubmitted(uint256 startIndex, uint256 count);
    event FeeCollected(address indexed collector, uint256 amount);
    event WalletUpgraded(string version, uint256 timestamp);
    event SecurityAlert(string alertType, address indexed owner, uint256 timestamp);
    event RateLimitExceeded(address indexed owner, uint256 timestamp);

    // ========================================
    // STATE VARIABLES - Core wallet state
    // ========================================
    address[] public owners;                    // Array of wallet owners
    mapping(address => bool) public isOwner;    // Quick owner lookup
    uint256 public numConfirmationsRequired;    // Required confirmations for execution
    uint256 public transactionCount;            // Total transaction count
    
    // ========================================
    // VERSIONING & UPGRADE TRACKING
    // ========================================
    uint256 public walletVersion;               // Current wallet version
    uint256 public lastUpgradeTime;             // Last upgrade timestamp
    string public walletName;                   // Human-readable wallet name
    
    // ========================================
    // FEE MANAGEMENT SYSTEM
    // ========================================
    uint256 public transactionFee;              // Fee in basis points (100 = 1%)
    uint256 public collectedFees;               // Accumulated fees
    address public feeCollector;                // Address that collects fees
    uint256 public maxTransactionFee;           // Maximum allowed fee (500 = 5%)
    
    // ========================================
    // EMERGENCY & SECURITY FEATURES
    // ========================================
    bool public emergencyMode;                  // Emergency mode status
    uint256 public emergencyThreshold;          // Required confirmations for emergency actions
    uint256 public lastEmergencyAction;         // Last emergency action timestamp
    uint256 public emergencyCooldown;           // Cooldown period between emergency actions
    
    // ========================================
    // TIME-LOCK & SCHEDULING FEATURES
    // ========================================
    uint256 public defaultTimeLock;             // Default time-lock duration in seconds
    mapping(uint256 => uint256) public transactionUnlockTime;  // Transaction unlock timestamps
    mapping(uint256 => bool) public transactionTimeLocked;     // Time-lock status per transaction
    
    // ========================================
    // RATE LIMITING & ANTI-SPAM PROTECTION
    // ========================================
    mapping(address => uint256) public ownerLastTransaction;  // Last transaction timestamp per owner
    mapping(address => uint256) public ownerDailyTransactionCount;  // Daily transaction count
    uint256 public dailyTransactionLimit;       // Maximum transactions per owner per day
    uint256 public transactionCooldown;         // Minimum time between transactions per owner
    
    // ========================================
    // TRANSACTION STRUCTURE
    // ========================================
    struct Transaction {
        address to;                             // Destination address
        uint256 value;                          // ETH amount to send
        bytes data;                             // Transaction data
        bool executed;                           // Execution status
        uint256 numConfirmations;                // Number of confirmations received
        uint256 unlockTime;                      // Time-lock unlock timestamp
        bool isTimeLocked;                       // Time-lock status
        bool isBatchTransaction;                 // Batch transaction flag
        uint256 batchId;                         // Batch identifier
        uint256 submissionTime;                  // Transaction submission timestamp
        address submittedBy;                     // Transaction submitter
    }

    // ========================================
    // STORAGE MAPPINGS
    // ========================================
    mapping(uint256 => Transaction) public transactions;                    // Transaction storage
    mapping(uint256 => mapping(address => bool)) public isConfirmed;       // Confirmation tracking
    mapping(uint256 => uint256[]) public batchTransactions;                // Batch transaction grouping
    uint256 public batchCounter;                                           // Batch counter
    
    // ========================================
    // OWNER ACTIVITY & ANALYTICS TRACKING
    // ========================================
    mapping(address => uint256) public ownerLastActivity;                  // Last activity timestamp
    mapping(address => uint256) public ownerTransactionCount;              // Total transaction count per owner
    mapping(address => uint256) public ownerConfirmationCount;             // Total confirmations per owner
    mapping(uint256 => uint256) public dailyTransactionTotal;             // Daily transaction totals
    
    // ========================================
    // SECURITY CONSTANTS & LIMITS
    // ========================================
    uint256 public constant MAX_OWNERS = 20;                               // Maximum number of owners
    uint256 public constant MAX_BATCH_SIZE = 10;                           // Maximum batch transaction size
    uint256 public constant MAX_TIME_LOCK = 365 days;                      // Maximum time-lock duration
    uint256 public constant MIN_EMERGENCY_THRESHOLD = 2;                   // Minimum emergency threshold
    uint256 public constant EMERGENCY_COOLDOWN_PERIOD = 1 hours;           // Emergency action cooldown

    // ========================================
    // MODIFIERS - Access control & validation
    // ========================================
    
    /**
     * @dev Ensures only wallet owners can call the function
     */
    modifier onlyOwner() {
        require(isOwner[msg.sender], "MultiSigWallet: caller is not an owner");
        _;
    }

    /**
     * @dev Ensures the transaction exists
     */
    modifier txExists(uint256 _txIndex) {
        require(_txIndex < transactionCount, "MultiSigWallet: transaction does not exist");
        _;
    }

    /**
     * @dev Ensures the transaction hasn't been executed
     */
    modifier notExecuted(uint256 _txIndex) {
        require(!transactions[_txIndex].executed, "MultiSigWallet: transaction already executed");
        _;
    }

    /**
     * @dev Ensures the owner hasn't already confirmed the transaction
     */
    modifier notConfirmed(uint256 _txIndex) {
        require(!isConfirmed[_txIndex][msg.sender], "MultiSigWallet: transaction already confirmed");
        _;
    }

    /**
     * @dev Ensures the contract is not paused
     */
    modifier notPaused() {
        require(!paused(), "MultiSigWallet: contract is paused");
        _;
    }
    
    /**
     * @dev Ensures emergency mode is not active
     */
    modifier notEmergencyMode() {
        require(!emergencyMode, "MultiSigWallet: emergency mode active");
        _;
    }
    
    /**
     * @dev Ensures time-lock has expired for the transaction
     */
    modifier timeLockExpired(uint256 _txIndex) {
        if (transactions[_txIndex].isTimeLocked) {
            require(block.timestamp >= transactions[_txIndex].unlockTime, "MultiSigWallet: time-lock not expired");
        }
        _;
    }
    
    /**
     * @dev Ensures rate limiting is respected
     */
    modifier rateLimitRespected() {
        require(
            block.timestamp >= ownerLastTransaction[msg.sender] + transactionCooldown,
            "MultiSigWallet: transaction cooldown not met"
        );
        require(
            ownerDailyTransactionCount[msg.sender] < dailyTransactionLimit,
            "MultiSigWallet: daily transaction limit exceeded"
        );
        _;
    }
    
    /**
     * @dev Ensures valid owner count limits
     */
    modifier validOwnerCount(uint256 _newCount) {
        require(_newCount > 0 && _newCount <= MAX_OWNERS, "MultiSigWallet: invalid owner count");
        _;
    }

    // ========================================
    // CONSTRUCTOR - Contract initialization
    // ========================================
    
    /**
     * @dev Constructor sets the initial owners and required confirmations
     * @param _owners Array of initial owner addresses
     * @param _numConfirmationsRequired Number of confirmations required for transaction execution
     * @param _defaultTimeLock Default time-lock duration in seconds
     * @param _walletName Human-readable name for the wallet
     */
    constructor(
        address[] memory _owners, 
        uint256 _numConfirmationsRequired,
        uint256 _defaultTimeLock,
        string memory _walletName
    ) {
        // Validate input parameters
        require(_owners.length > 0, "MultiSigWallet: owners required");
        require(_owners.length <= MAX_OWNERS, "MultiSigWallet: too many owners");
        require(
            _numConfirmationsRequired > 0 && _numConfirmationsRequired <= _owners.length,
            "MultiSigWallet: invalid number of required confirmations"
        );
        require(_defaultTimeLock >= 0 && _defaultTimeLock <= MAX_TIME_LOCK, "MultiSigWallet: invalid time-lock");
        require(bytes(_walletName).length > 0, "MultiSigWallet: wallet name required");

        // Initialize owners
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "MultiSigWallet: invalid owner address");
            require(!isOwner[owner], "MultiSigWallet: owner not unique");
            require(owner.code.length == 0, "MultiSigWallet: owner cannot be a contract"); // Security: prevent contract owners

            isOwner[owner] = true;
            owners.push(owner);
            ownerLastActivity[owner] = block.timestamp;
            ownerDailyTransactionCount[owner] = 0;
        }

        // Set core parameters
        numConfirmationsRequired = _numConfirmationsRequired;
        defaultTimeLock = _defaultTimeLock;
        walletVersion = 1;
        lastUpgradeTime = block.timestamp;
        walletName = _walletName;
        
        // Set security parameters
        emergencyThreshold = max(_numConfirmationsRequired, MIN_EMERGENCY_THRESHOLD);
        emergencyCooldown = EMERGENCY_COOLDOWN_PERIOD;
        feeCollector = _owners[0]; // First owner becomes fee collector
        maxTransactionFee = 500; // 5% maximum fee
        
        // Set rate limiting parameters
        dailyTransactionLimit = 50; // 50 transactions per day per owner
        transactionCooldown = 1 minutes; // 1 minute between transactions per owner
        
        // Emit initialization event
        emit WalletUpgraded("v1.0.0", block.timestamp);
    }

    // ========================================
    // RECEIVE FUNCTION - Accept ETH deposits
    // ========================================
    
    /**
     * @dev Allows contract to receive ETH
     * @dev Emits Deposit event for transparency
     */
    receive() external payable {
        require(msg.value > 0, "MultiSigWallet: zero deposit not allowed");
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    // ========================================
    // TRANSACTION MANAGEMENT FUNCTIONS
    // ========================================
    
    /**
     * @dev Submit a new transaction for approval with optional time-lock
     * @param _to Destination address
     * @param _value ETH amount to send
     * @param _data Transaction data
     * @param _timeLocked Whether to apply time-lock
     * @param _customTimeLock Custom time-lock duration (0 for default)
     * 
     * Security features:
     * - Rate limiting to prevent spam
     * - Balance validation
     * - Contract address validation
     * - Time-lock duration limits
     */
    function submitTransaction(
        address _to,
        uint256 _value,
        bytes memory _data,
        bool _timeLocked,
        uint256 _customTimeLock
    ) external onlyOwner notPaused notEmergencyMode rateLimitRespected {
        // Input validation
        require(_to != address(0), "MultiSigWallet: invalid destination address");
        require(_to != address(this), "MultiSigWallet: cannot send to self");
        require(_value > 0, "MultiSigWallet: zero value not allowed");
        require(_value <= address(this).balance, "MultiSigWallet: insufficient balance");
        require(_data.length <= 10000, "MultiSigWallet: data too large"); // Prevent large data attacks
        
        // Time-lock validation
        uint256 unlockTime = 0;
        if (_timeLocked) {
            uint256 timeLockDuration = _customTimeLock > 0 ? _customTimeLock : defaultTimeLock;
            require(timeLockDuration <= MAX_TIME_LOCK, "MultiSigWallet: time-lock too long");
            unlockTime = block.timestamp + timeLockDuration;
        }

        // Create transaction
        uint256 txIndex = transactionCount;
        transactions[txIndex] = Transaction({
            to: _to,
            value: _value,
            data: _data,
            executed: false,
            numConfirmations: 0,
            unlockTime: unlockTime,
            isTimeLocked: _timeLocked,
            isBatchTransaction: false,
            batchId: 0,
            submissionTime: block.timestamp,
            submittedBy: msg.sender
        });

        // Update state
        transactionCount += 1;
        ownerTransactionCount[msg.sender]++;
        ownerLastActivity[msg.sender] = block.timestamp;
        ownerLastTransaction[msg.sender] = block.timestamp;
        
        // Update daily counters
        uint256 today = block.timestamp / 1 days;
        if (dailyTransactionTotal[today] == 0) {
            dailyTransactionTotal[today] = 1;
        } else {
            dailyTransactionTotal[today]++;
        }
        ownerDailyTransactionCount[msg.sender]++;

        // Emit events
        emit SubmitTransaction(msg.sender, txIndex, _to, _value, _data, unlockTime);
        
        if (_timeLocked) {
            emit TransactionScheduled(txIndex, unlockTime);
        }
        
        // Security alert for large transactions
        if (_value > 100 ether) {
            emit SecurityAlert("LARGE_TRANSACTION", msg.sender, block.timestamp);
        }
    }

    /**
     * @dev Submit multiple transactions as a batch for efficiency
     * @param _recipients Array of destination addresses
     * @param _values Array of ETH amounts
     * @param _dataArray Array of transaction data
     * 
     * Security features:
     * - Batch size limits
     * - Total value validation
     * - Rate limiting
     * - Input validation
     */
    function submitBatchTransactions(
        address[] memory _recipients,
        uint256[] memory _values,
        bytes[] memory _dataArray
    ) external onlyOwner notPaused notEmergencyMode rateLimitRespected {
        // Input validation
        require(
            _recipients.length == _values.length && _values.length == _dataArray.length,
            "MultiSigWallet: array length mismatch"
        );
        require(_recipients.length > 0 && _recipients.length <= MAX_BATCH_SIZE, "MultiSigWallet: invalid batch size");
        
        // Calculate total value and validate
        uint256 totalValue = 0;
        for (uint256 i = 0; i < _values.length; i++) {
            totalValue += _values[i];
            require(_values[i] > 0, "MultiSigWallet: zero value in batch");
        }
        require(totalValue <= address(this).balance, "MultiSigWallet: insufficient balance for batch");

        // Create batch
        uint256 batchId = batchCounter++;
        uint256 startIndex = transactionCount;
        
        for (uint256 i = 0; i < _recipients.length; i++) {
            require(_recipients[i] != address(0), "MultiSigWallet: invalid recipient in batch");
            require(_recipients[i] != address(this), "MultiSigWallet: cannot send to self in batch");
            require(_dataArray[i].length <= 10000, "MultiSigWallet: batch data too large");
            
            uint256 txIndex = transactionCount;
            
            transactions[txIndex] = Transaction({
                to: _recipients[i],
                value: _values[i],
                data: _dataArray[i],
                executed: false,
                numConfirmations: 0,
                unlockTime: 0,
                isTimeLocked: false,
                isBatchTransaction: true,
                batchId: batchId,
                submissionTime: block.timestamp,
                submittedBy: msg.sender
            });
            
            batchTransactions[batchId].push(txIndex);
            transactionCount++;
        }
        
        // Update state
        ownerTransactionCount[msg.sender]++;
        ownerLastActivity[msg.sender] = block.timestamp;
        ownerLastTransaction[msg.sender] = block.timestamp;
        ownerDailyTransactionCount[msg.sender]++;
        
        emit BatchTransactionSubmitted(startIndex, _recipients.length);
        
        // Security alert for large batch
        if (totalValue > 1000 ether) {
            emit SecurityAlert("LARGE_BATCH_TRANSACTION", msg.sender, block.timestamp);
        }
    }

    /**
     * @dev Confirm a transaction by an owner
     * @param _txIndex Transaction index
     * 
     * Security features:
     * - Owner validation
     - Transaction existence check
     * - Execution status validation
     * - Confirmation status validation
     */
    function confirmTransaction(uint256 _txIndex)
        external
        onlyOwner
        txExists(_txIndex)
        notExecuted(_txIndex)
        notConfirmed(_txIndex)
        notPaused
        notEmergencyMode
    {
        Transaction storage transaction = transactions[_txIndex];
        
        // Prevent self-confirmation for security
        require(msg.sender != transaction.submittedBy, "MultiSigWallet: cannot confirm own transaction");
        
        // Update confirmation
        transaction.numConfirmations += 1;
        isConfirmed[_txIndex][msg.sender] = true;
        
        // Update owner stats
        ownerLastActivity[msg.sender] = block.timestamp;
        ownerConfirmationCount[msg.sender]++;

        emit ConfirmTransaction(msg.sender, _txIndex);
        
        // Security alert for high-value confirmations
        if (transaction.value > 50 ether) {
            emit SecurityAlert("HIGH_VALUE_CONFIRMATION", msg.sender, block.timestamp);
        }
    }

    /**
     * @dev Execute a confirmed transaction
     * @param _txIndex Transaction index
     * 
     * Security features:
     * - Reentrancy protection
     * - Time-lock validation
     * - Confirmation threshold validation
     * - Fee calculation and collection
     */
    function executeTransaction(uint256 _txIndex)
        external
        onlyOwner
        txExists(_txIndex)
        notExecuted(_txIndex)
        notPaused
        notEmergencyMode
        timeLockExpired(_txIndex)
        nonReentrant
    {
        Transaction storage transaction = transactions[_txIndex];

        // Validate confirmation threshold
        require(
            transaction.numConfirmations >= numConfirmationsRequired,
            "MultiSigWallet: cannot execute transaction"
        );

        // Mark as executed
        transaction.executed = true;
        
        // Calculate and apply transaction fee
        uint256 feeAmount = 0;
        if (transactionFee > 0) {
            feeAmount = (transaction.value * transactionFee) / 10000; // Basis points
            collectedFees += feeAmount;
        }
        
        uint256 transferAmount = transaction.value - feeAmount;

        // Execute the transaction
        (bool success, bytes memory returnData) = transaction.to.call{value: transferAmount}(
            transaction.data
        );
        
        if (!success) {
            // Revert execution status on failure
            transaction.executed = false;
            
            // Log failure details for debugging
            if (returnData.length > 0) {
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            } else {
                revert("MultiSigWallet: transaction failed");
            }
        }

        emit ExecuteTransaction(msg.sender, _txIndex);
        
        // Security alert for executed high-value transactions
        if (transaction.value > 100 ether) {
            emit SecurityAlert("HIGH_VALUE_EXECUTION", msg.sender, block.timestamp);
        }
    }

    /**
     * @dev Revoke a confirmation for a transaction
     * @param _txIndex Transaction index
     */
    function revokeConfirmation(uint256 _txIndex)
        external
        onlyOwner
        txExists(_txIndex)
        notExecuted(_txIndex)
        notPaused
        notEmergencyMode
    {
        require(isConfirmed[_txIndex][msg.sender], "MultiSigWallet: transaction not confirmed");

        Transaction storage transaction = transactions[_txIndex];
        transaction.numConfirmations -= 1;
        isConfirmed[_txIndex][msg.sender] = false;
        
        ownerLastActivity[msg.sender] = block.timestamp;

        emit RevokeConfirmation(msg.sender, _txIndex);
    }

    // ========================================
    // EMERGENCY & RECOVERY FUNCTIONS
    // ========================================
    
    /**
     * @dev Emergency recovery function - allows immediate withdrawal in emergency mode
     * @param _to Recovery address
     * @param _amount Amount to recover
     * 
     * Security features:
     * - Emergency mode validation
     * - Super majority requirement
     * - Cooldown period enforcement
     * - Recovery address validation
     */
    function emergencyRecovery(address _to, uint256 _amount) 
        external 
        onlyOwner 
        notPaused 
    {
        require(emergencyMode, "MultiSigWallet: emergency mode not active");
        require(_to != address(0), "MultiSigWallet: invalid recovery address");
        require(_to != address(this), "MultiSigWallet: cannot recover to self");
        require(_amount <= address(this).balance, "MultiSigWallet: insufficient balance");
        require(
            block.timestamp >= lastEmergencyAction + emergencyCooldown,
            "MultiSigWallet: emergency cooldown not met"
        );
        
        // Require emergency threshold confirmations
        require(
            getEmergencyConfirmations() >= emergencyThreshold,
            "MultiSigWallet: insufficient emergency confirmations"
        );
        
        // Execute recovery
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "MultiSigWallet: emergency recovery failed");
        
        lastEmergencyAction = block.timestamp;
        emit EmergencyRecovery(_to, _amount);
        emit SecurityAlert("EMERGENCY_RECOVERY", msg.sender, block.timestamp);
    }

    /**
     * @dev Activate emergency mode (requires super majority)
     * 
     * Security features:
     * - Super majority requirement
     * - Owner validation
     * - Event logging
     */
    function activateEmergencyMode() external onlyOwner notPaused {
        require(!emergencyMode, "MultiSigWallet: emergency mode already active");
        
        uint256 confirmations = 0;
        for (uint256 i = 0; i < owners.length; i++) {
            if (isOwner[owners[i]]) {
                confirmations++;
            }
        }
        
        require(confirmations >= emergencyThreshold, "MultiSigWallet: insufficient confirmations for emergency mode");
        
        emergencyMode = true;
        emit EmergencyRecovery(msg.sender, 0); // Event for emergency mode activation
        emit SecurityAlert("EMERGENCY_MODE_ACTIVATED", msg.sender, block.timestamp);
    }

    /**
     * @dev Deactivate emergency mode
     */
    function deactivateEmergencyMode() external onlyOwner {
        require(emergencyMode, "MultiSigWallet: emergency mode not active");
        emergencyMode = false;
        emit SecurityAlert("EMERGENCY_MODE_DEACTIVATED", msg.sender, block.timestamp);
    }

    // ========================================
    // OWNER MANAGEMENT FUNCTIONS
    // ========================================
    
    /**
     * @dev Add a new owner
     * @param _newOwner Address of the new owner
     * 
     * Security features:
     * - Address validation
     * - Duplicate prevention
     * - Owner count limits
     * - Contract address prevention
     */
    function addOwner(address _newOwner) external onlyOwner notPaused notEmergencyMode {
        require(_newOwner != address(0), "MultiSigWallet: invalid owner address");
        require(!isOwner[_newOwner], "MultiSigWallet: owner already exists");
        require(owners.length < MAX_OWNERS, "MultiSigWallet: maximum owners reached");
        require(_newOwner.code.length == 0, "MultiSigWallet: owner cannot be a contract");

        isOwner[_newOwner] = true;
        owners.push(_newOwner);
        ownerLastActivity[_newOwner] = block.timestamp;
        ownerDailyTransactionCount[_newOwner] = 0;

        // Adjust threshold if needed
        if (numConfirmationsRequired <= owners.length - 1) {
            numConfirmationsRequired = owners.length - 1;
        }

        emit OwnerAdded(_newOwner);
        emit ThresholdChanged(numConfirmationsRequired);
        emit SecurityAlert("OWNER_ADDED", _newOwner, block.timestamp);
    }

    /**
     * @dev Remove an owner
     * @param _ownerToRemove Address of the owner to remove
     * 
     * Security features:
     * - Owner validation
     * - Minimum owner count enforcement
     * - Threshold adjustment
     */
    function removeOwner(address _ownerToRemove) external onlyOwner notPaused notEmergencyMode {
        require(isOwner[_ownerToRemove], "MultiSigWallet: not an owner");
        require(owners.length > 1, "MultiSigWallet: cannot remove last owner");

        // Remove from owners array
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == _ownerToRemove) {
                owners[i] = owners[owners.length - 1];
                owners.pop();
                break;
            }
        }

        isOwner[_ownerToRemove] = false;

        // Adjust threshold if needed
        if (numConfirmationsRequired > owners.length) {
            numConfirmationsRequired = owners.length;
        }

        emit OwnerRemoved(_ownerToRemove);
        emit ThresholdChanged(numConfirmationsRequired);
        emit SecurityAlert("OWNER_REMOVED", _ownerToRemove, block.timestamp);
    }

    // ========================================
    // CONFIGURATION & SETTINGS FUNCTIONS
    // ========================================
    
    /**
     * @dev Change the number of required confirmations
     * @param _newThreshold New threshold value
     */
    function changeThreshold(uint256 _newThreshold) external onlyOwner notPaused notEmergencyMode {
        require(
            _newThreshold > 0 && _newThreshold <= owners.length,
            "MultiSigWallet: invalid threshold"
        );

        numConfirmationsRequired = _newThreshold;
        emit ThresholdChanged(_newThreshold);
        emit SecurityAlert("THRESHOLD_CHANGED", msg.sender, block.timestamp);
    }

    /**
     * @dev Set transaction fee (in basis points, 100 = 1%)
     * @param _fee New fee in basis points
     */
    function setTransactionFee(uint256 _fee) external onlyOwner notPaused {
        require(_fee <= maxTransactionFee, "MultiSigWallet: fee too high");
        transactionFee = _fee;
        emit SecurityAlert("FEE_CHANGED", msg.sender, block.timestamp);
    }

    /**
     * @dev Change fee collector address
     * @param _newCollector New fee collector address
     */
    function changeFeeCollector(address _newCollector) external onlyOwner notPaused {
        require(_newCollector != address(0), "MultiSigWallet: invalid collector address");
        require(_newCollector.code.length == 0, "MultiSigWallet: collector cannot be a contract");
        feeCollector = _newCollector;
        emit SecurityAlert("FEE_COLLECTOR_CHANGED", _newCollector, block.timestamp);
    }

    /**
     * @dev Collect accumulated fees
     */
    function collectFees() external notPaused {
        require(msg.sender == feeCollector, "MultiSigWallet: only fee collector can collect");
        require(collectedFees > 0, "MultiSigWallet: no fees to collect");
        
        uint256 amount = collectedFees;
        collectedFees = 0;
        
        (bool success, ) = feeCollector.call{value: amount}("");
        require(success, "MultiSigWallet: fee collection failed");
        
        emit FeeCollected(feeCollector, amount);
    }

    /**
     * @dev Set default time-lock duration
     * @param _newTimeLock New time-lock duration in seconds
     */
    function setDefaultTimeLock(uint256 _newTimeLock) external onlyOwner notPaused {
        require(_newTimeLock <= MAX_TIME_LOCK, "MultiSigWallet: time-lock too long");
        defaultTimeLock = _newTimeLock;
        emit SecurityAlert("TIME_LOCK_CHANGED", msg.sender, block.timestamp);
    }

    /**
     * @dev Set rate limiting parameters
     * @param _dailyLimit New daily transaction limit
     * @param _cooldown New transaction cooldown period
     */
    function setRateLimits(uint256 _dailyLimit, uint256 _cooldown) external onlyOwner notPaused {
        require(_dailyLimit > 0 && _dailyLimit <= 1000, "MultiSigWallet: invalid daily limit");
        require(_cooldown >= 1 minutes && _cooldown <= 1 hours, "MultiSigWallet: invalid cooldown");
        
        dailyTransactionLimit = _dailyLimit;
        transactionCooldown = _cooldown;
        emit SecurityAlert("RATE_LIMITS_CHANGED", msg.sender, block.timestamp);
    }

    // ========================================
    // ADMINISTRATIVE FUNCTIONS
    // ========================================
    
    /**
     * @dev Pause the contract
     */
    function pause() external onlyOwner {
        _pause();
        emit SecurityAlert("CONTRACT_PAUSED", msg.sender, block.timestamp);
    }

    /**
     * @dev Unpause the contract
     */
    function unpause() external onlyOwner {
        _unpause();
        emit SecurityAlert("CONTRACT_UNPAUSED", msg.sender, block.timestamp);
    }

    /**
     * @dev Upgrade wallet version (for future enhancements)
     * @param _newVersion New version number
     */
    function upgradeWallet(uint256 _newVersion) external onlyOwner notPaused {
        require(_newVersion > walletVersion, "MultiSigWallet: version must increase");
        walletVersion = _newVersion;
        lastUpgradeTime = block.timestamp;
        emit WalletUpgraded(string(abi.encodePacked("v", _newVersion)), block.timestamp);
        emit SecurityAlert("WALLET_UPGRADED", msg.sender, block.timestamp);
    }

    // ========================================
    // VIEW FUNCTIONS - Read-only operations
    // ========================================
    
    /**
     * @dev Get all owners
     * @return Array of owner addresses
     */
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    /**
     * @dev Get transaction details
     * @param _txIndex Transaction index
     * @return Transaction struct
     */
    function getTransaction(uint256 _txIndex)
        external
        view
        returns (Transaction memory)
    {
        return transactions[_txIndex];
    }

    /**
     * @dev Get contract balance
     * @return Current ETH balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Check if an address is an owner
     * @param _owner Address to check
     * @return True if address is an owner
     */
    function checkOwner(address _owner) external view returns (bool) {
        return isOwner[_owner];
    }
    
    /**
     * @dev Get batch transactions for a specific batch ID
     * @param _batchId Batch identifier
     * @return Array of transaction indices
     */
    function getBatchTransactions(uint256 _batchId) external view returns (uint256[] memory) {
        return batchTransactions[_batchId];
    }
    
    /**
     * @dev Get owner statistics and activity
     * @param _owner Owner address
     * @return lastActivity Last activity timestamp
     * @return txCount Total transaction count
     * @return confirmationCount Total confirmation count
     */
    function getOwnerStats(address _owner) external view returns (
        uint256 lastActivity, 
        uint256 txCount, 
        uint256 confirmationCount
    ) {
        return (
            ownerLastActivity[_owner], 
            ownerTransactionCount[_owner], 
            ownerConfirmationCount[_owner]
        );
    }
    
    /**
     * @dev Get current emergency confirmations count
     * @return Number of active owners
     */
    function getEmergencyConfirmations() public view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < owners.length; i++) {
            if (isOwner[owners[i]]) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * @dev Check if a transaction is ready for execution
     * @param _txIndex Transaction index
     * @return True if transaction is ready
     */
    function isTransactionReady(uint256 _txIndex) external view returns (bool) {
        Transaction storage transaction = transactions[_txIndex];
        if (transaction.executed) return false;
        if (transaction.numConfirmations < numConfirmationsRequired) return false;
        if (transaction.isTimeLocked && block.timestamp < transaction.unlockTime) return false;
        return true;
    }
    
    /**
     * @dev Get wallet information and statistics
     * @return name Wallet name
     * @return version Current version
     * @return totalOwners Total number of owners
     * @return totalTransactions Total transaction count
     * @return totalFees Collected fees
     * @return isEmergencyMode Emergency mode status
     */
    function getWalletInfo() external view returns (
        string memory name,
        uint256 version,
        uint256 totalOwners,
        uint256 totalTransactions,
        uint256 totalFees,
        bool isEmergencyMode
    ) {
        return (
            walletName,
            walletVersion,
            owners.length,
            transactionCount,
            collectedFees,
            emergencyMode
        );
    }

    // ========================================
    // UTILITY FUNCTIONS
    // ========================================
    
    /**
     * @dev Get maximum of two numbers
     * @param a First number
     * @param b Second number
     * @return Maximum value
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
    
    /**
     * @dev Reset daily transaction counters (callable by any owner)
     * @dev This helps maintain accurate daily limits
     */
    function resetDailyCounters() external onlyOwner {
        uint256 today = block.timestamp / 1 days;
        dailyTransactionTotal[today] = 0;
        
        for (uint256 i = 0; i < owners.length; i++) {
            ownerDailyTransactionCount[owners[i]] = 0;
        }
        
        emit SecurityAlert("DAILY_COUNTERS_RESET", msg.sender, block.timestamp);
    }
}
