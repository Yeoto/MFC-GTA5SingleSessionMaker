#pragma once

#include <Windows.h>
#include <netfw.h>

#define OUTBOUND_RULE_TCP_NAME L"GTA5 Outbound Rule-TCP"
#define OUTBOUND_RULE_UDP_NAME L"GTA5 Outbound Rule-UDP"

class CFirewallMaker
{
public:
	CFirewallMaker(void);
	~CFirewallMaker(void);

public:
	static int MakeOutboundRule();

	static void GetStatusOutboundRule(bool& bIsExist, bool& bIsEnable);
	static void EnableOutboundRule(bool bEnable);

private:
	static HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);
};

