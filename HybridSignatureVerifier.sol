// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title HybridSignatureVerifier
 * @dev Контракт для приёма и хранения гибридных подписей (Ed25519 + ML-DSA-65).
 *
 * В текущей реализации верификация постквантовой подписи выполняется off-chain,
 * а контракт служит для фиксации стоимости газа и хранения данных.
 * В будущем верификация может быть вынесена в прекомпилированный контракт.
 */
contract HybridSignatureVerifier {

    // Структура для хранения информации о гибридной подписи
    struct HybridSignature {
        address sender;           // Адрес отправителя транзакции
        bytes32 txHash;           // Хэш транзакции (для привязки)
        bytes pqcSignature;       // Постквантовая подпись (ML-DSA-65)
        bytes pqcPublicKey;       // Постквантовый публичный ключ
        uint256 timestamp;        // Время подтверждения
        bool verified;            // Флаг верификации (будет установлен off-chain)
    }

    // Массив для хранения всех принятых подписей
    HybridSignature[] public signatures;

    // События для логирования и измерения газа
    event SignatureSubmitted(
        address indexed sender,
        bytes32 indexed txHash,
        uint256 signatureId,
        uint256 timestamp
    );

    event SignatureVerified(
        uint256 indexed signatureId,
        bool verified,
        string reason
    );

    // Модификатор для ограничения доступа (только владелец контракта)
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    /**
     * @dev Принимает постквантовую подпись и публичный ключ.
     * @param pqcSignature Подпись ML-DSA-65
     * @param pqcPublicKey Публичный ключ ML-DSA-65
     * @param txHash Хэш подписанной транзакции
     */
    function submitSignature(
        bytes calldata pqcSignature,
        bytes calldata pqcPublicKey,
        bytes32 txHash
    ) external {
        // Проверка минимальной длины подписи (ML-DSA-65: ~3293 байта)
        require(pqcSignature.length > 3000, "Signature too short");
        require(pqcPublicKey.length > 1000, "Public key too short");

        // Сохраняем подпись
        uint256 signatureId = signatures.length;
        signatures.push(HybridSignature({
            sender: msg.sender,
            txHash: txHash,
            pqcSignature: pqcSignature,
            pqcPublicKey: pqcPublicKey,
            timestamp: block.timestamp,
            verified: false
        }));

        // Логируем событие для измерения газа
        emit SignatureSubmitted(msg.sender, txHash, signatureId, block.timestamp);
    }

    /**
     * @dev Устанавливает статус верификации подписи (вызывается владельцем).
     * В реальной реализации этот метод может вызываться прекомпилированным контрактом.
     * @param signatureId Идентификатор подписи в массиве
     * @param verified Статус верификации
     * @param reason Причина (для отладки)
     */
    function setVerificationStatus(
        uint256 signatureId,
        bool verified,
        string calldata reason
    ) external onlyOwner {
        require(signatureId < signatures.length, "Invalid signature ID");

        signatures[signatureId].verified = verified;
        emit SignatureVerified(signatureId, verified, reason);
    }

    /**
     * @dev Возвращает количество сохранённых подписей.
     */
    function getSignaturesCount() external view returns (uint256) {
        return signatures.length;
    }

    /**
     * @dev Возвращает информацию о конкретной подписи.
     * @param signatureId Идентификатор подписи
     */
    function getSignature(uint256 signatureId) external view returns (
        address sender,
        bytes32 txHash,
        bytes memory pqcSignature,
        bytes memory pqcPublicKey,
        uint256 timestamp,
        bool verified
    ) {
        require(signatureId < signatures.length, "Invalid signature ID");
        HybridSignature memory sig = signatures[signatureId];
        return (
            sig.sender,
            sig.txHash,
            sig.pqcSignature,
            sig.pqcPublicKey,
            sig.timestamp,
            sig.verified
        );
    }

    /**
     * @dev Заглушка для будущей интеграции с прекомпилированным контрастом.
     * В реальной реализации здесь будет вызов предустановленного контракта
     * для верификации ML-DSA-65 подписи.
     * @param message Сообщение (хэш транзакции)
     * @param signature Подпись ML-DSA-65
     * @param publicKey Публичный ключ ML-DSA-65
     * @return true если подпись действительна
     */
    function verifyPQCSignature(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) public pure returns (bool) {
        // В текущей реализации — заглушка, возвращающая true для любых корректно сформированных данных
        // В реальной системе здесь должен быть вызов прекомпилированного контраста по адресу, например, 0x09

        // Простейшая проверка: подпись и ключ не пустые
        if (signature.length == 0 || publicKey.length == 0) {
            return false;
        }

        // ВАЖНО: Это заглушка! Реальная верификация требует прекомпилированного контракта.
        // Для прототипа считаем, что все переданные данные корректны.
        return true;
    }
}
