#include "stdafx.h"
#include "FirewallMaker.h"

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

CFirewallMaker::CFirewallMaker(void)
{
}


CFirewallMaker::~CFirewallMaker(void)
{
}

int CFirewallMaker::MakeOutboundRule()
{
	HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRuleUDP = NULL;
	INetFwRule *pFwRuleTCP = NULL;

    long CurrentProfilesBitMask = 0;

	BSTR bstrRuleUDPName = SysAllocString(OUTBOUND_RULE_UDP_NAME);
	BSTR bstrRuleTCPName = SysAllocString(OUTBOUND_RULE_TCP_NAME);
    BSTR bstrRuleDescription = SysAllocString(L"Block outbound network traffic port");
    BSTR bstrRuleLPorts = SysAllocString(L"6672,61455,61457,61456,61458");

    // Initialize COM.
    hrComInit = CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
        if (FAILED(hrComInit))
            goto Cleanup;

    // Retrieve INetFwPolicy2
    hr = WFCOMInitialize(&pNetFwPolicy);
    if (FAILED(hr))
        goto Cleanup;

    // Retrieve INetFwRules
    hr = pNetFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr))
        goto Cleanup;

	CurrentProfilesBitMask = NET_FW_PROFILE2_ALL;

    // Create a new Firewall Rule object.
    hr = CoCreateInstance(
                __uuidof(NetFwRule),
                NULL,
                CLSCTX_INPROC_SERVER,
                __uuidof(INetFwRule),
                (void**)&pFwRuleUDP);
    if (FAILED(hr))
        goto Cleanup;

	hr = CoCreateInstance(
                __uuidof(NetFwRule),
                NULL,
                CLSCTX_INPROC_SERVER,
                __uuidof(INetFwRule),
                (void**)&pFwRuleTCP);
    if (FAILED(hr))
        goto Cleanup;

    // Populate the Firewall Rule object
	pFwRuleUDP->put_Action(NET_FW_ACTION_BLOCK);
    pFwRuleUDP->put_Direction(NET_FW_RULE_DIR_OUT);
    pFwRuleUDP->put_Name(bstrRuleUDPName);
    pFwRuleUDP->put_Description(bstrRuleDescription);
    pFwRuleUDP->put_Protocol(NET_FW_IP_PROTOCOL_UDP);
    pFwRuleUDP->put_Profiles(CurrentProfilesBitMask);
	pFwRuleUDP->put_RemotePorts(bstrRuleLPorts);
    pFwRuleUDP->put_Enabled(VARIANT_FALSE);

    // Add the Firewall Rule
    hr = pFwRules->Add(pFwRuleUDP);
    if (FAILED(hr))
        goto Cleanup;

	pFwRuleTCP->put_Action(NET_FW_ACTION_BLOCK);
    pFwRuleTCP->put_Direction(NET_FW_RULE_DIR_OUT);
    pFwRuleTCP->put_Name(bstrRuleTCPName);
    pFwRuleTCP->put_Description(bstrRuleDescription);
    pFwRuleTCP->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
    pFwRuleTCP->put_Profiles(CurrentProfilesBitMask);
	pFwRuleTCP->put_RemotePorts(bstrRuleLPorts);
    pFwRuleTCP->put_Enabled(VARIANT_FALSE);

    // Add the Firewall Rule
    hr = pFwRules->Add(pFwRuleTCP);
    if (FAILED(hr))
        goto Cleanup;

Cleanup:
    SysFreeString(bstrRuleUDPName);
    SysFreeString(bstrRuleTCPName);
    SysFreeString(bstrRuleDescription);
    SysFreeString(bstrRuleLPorts);

    if (pFwRuleUDP != NULL)
        pFwRuleUDP->Release();

	if (pFwRuleTCP != NULL)
        pFwRuleTCP->Release();

    if (pFwRules != NULL)
        pFwRules->Release();

    if (pNetFwPolicy != NULL)
        pNetFwPolicy->Release();

    if (SUCCEEDED(hrComInit))
        CoUninitialize();
   
    return 0;
}

void CFirewallMaker::GetStatusOutboundRule(bool& bIsExist, bool& bIsEnable)
{
	bIsExist = false;
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	BSTR bstrRuleUDPName = SysAllocString(OUTBOUND_RULE_UDP_NAME);
	BSTR bstrRuleTCPName = SysAllocString(OUTBOUND_RULE_TCP_NAME);
    INetFwPolicy2 *pNetFwPolicy = NULL;
	INetFwRules *pFwRules = NULL;
	INetFwRule* pFwRule = NULL;

	 // Initialize COM.
    hrComInit = CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
        if (FAILED(hrComInit))
            goto Cleanup;

	hr = WFCOMInitialize(&pNetFwPolicy);

	hr = pNetFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr))
        goto Cleanup;

	long lRuleCnt = 0;
	hr = pFwRules->get_Count(&lRuleCnt);
    if (FAILED(hr))
        goto Cleanup;

	VARIANT_BOOL vBool;
	bool bEnableUDP = false, bEnableTCP = false;

	//////////////////////////////////////////
	//UDP
	hr = pFwRules->Item(bstrRuleUDPName, &pFwRule);
    if (FAILED(hr))
        goto Cleanup;

	hr = pFwRule->get_Enabled(&vBool);
	if (FAILED(hr))
        goto Cleanup;

	bEnableUDP = (vBool == VARIANT_TRUE ? true : false);
	//////////////////////////////////////////

	//////////////////////////////////////////
	//TCP
	hr = pFwRules->Item(bstrRuleTCPName, &pFwRule);
    if (FAILED(hr))
        goto Cleanup;

	hr = pFwRule->get_Enabled(&vBool);
	if (FAILED(hr))
        goto Cleanup;

	bEnableTCP = (vBool == VARIANT_TRUE ? true : false);
	//////////////////////////////////////////

	bIsExist = true;
	bIsEnable = bEnableUDP && bEnableTCP;

Cleanup:
    SysFreeString(bstrRuleUDPName);
    SysFreeString(bstrRuleTCPName);

	if (pFwRule != NULL)
        pFwRule->Release();

	if (pFwRules != NULL)
        pFwRules->Release();

	if (pNetFwPolicy != NULL)
        pNetFwPolicy->Release();

	// Uninitialize COM.
    if (SUCCEEDED(hrComInit))
        CoUninitialize();
}

HRESULT CFirewallMaker::WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;

	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2), 
		NULL, 
		CLSCTX_INPROC_SERVER, 
		__uuidof(INetFwPolicy2), 
		(void**)ppNetFwPolicy2);

	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
		goto Cleanup;        
	}

Cleanup:
	return hr;
}

void CFirewallMaker::EnableOutboundRule(bool bEnable)
{
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	BSTR bstrRuleUDPName = SysAllocString(OUTBOUND_RULE_UDP_NAME);
	BSTR bstrRuleTCPName = SysAllocString(OUTBOUND_RULE_TCP_NAME);
    INetFwPolicy2 *pNetFwPolicy = NULL;
	INetFwRules *pFwRules = NULL;
	INetFwRule* pFwRule = NULL;

	 // Initialize COM.
    hrComInit = CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
        if (FAILED(hrComInit))
            goto Cleanup;

	hr = WFCOMInitialize(&pNetFwPolicy);

	hr = pNetFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr))
        goto Cleanup;

	long lRuleCnt = 0;
	hr = pFwRules->get_Count(&lRuleCnt);
    if (FAILED(hr))
        goto Cleanup;

	VARIANT_BOOL vBool = bEnable == true ? VARIANT_TRUE : VARIANT_FALSE;;
	//////////////////////////////////////////
	//UDP
	hr = pFwRules->Item(bstrRuleUDPName, &pFwRule);
    if (FAILED(hr))
        goto Cleanup;

	hr = pFwRule->put_Enabled(vBool);
	if (FAILED(hr))
        goto Cleanup;
	//////////////////////////////////////////

	//////////////////////////////////////////
	//TCP
	hr = pFwRules->Item(bstrRuleTCPName, &pFwRule);
    if (FAILED(hr))
        goto Cleanup;

	hr = pFwRule->put_Enabled(vBool);
	if (FAILED(hr))
        goto Cleanup;
	//////////////////////////////////////////

Cleanup:
    SysFreeString(bstrRuleUDPName);
    SysFreeString(bstrRuleTCPName);

	if (pFwRule != NULL)
        pFwRule->Release();

	if (pFwRules != NULL)
        pFwRules->Release();

	if (pNetFwPolicy != NULL)
        pNetFwPolicy->Release();

	// Uninitialize COM.
    if (SUCCEEDED(hrComInit))
        CoUninitialize();
}