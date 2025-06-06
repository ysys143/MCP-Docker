from fastmcp import FastMCP
import asyncio

mcp = FastMCP("Weather MCP Server")

# 원격 OAuth2 MCP 도구 추가
# `mcp-oauth2-web-server`는 docker-compose 네트워크 내의 서비스 이름입니다.
# `8081`은 oauth2-web-server가 노출하는 포트이며, `/mcp_tools`는 FastMCP 앱이 마운트된 경로입니다.
# mcp.add_remote_tools("http://mcp-oauth2-web-server:8081/mcp_tools") # 재솔님의 요청에 따라 제거

@mcp.tool
async def get_weather(city: str) -> dict:
    """지정된 도시의 현재 날씨 정보를 반환합니다."""
    # 실제 날씨 API 호출 대신 가상의 날씨 데이터를 반환합니다.
    await asyncio.sleep(0.1) # 비동기 작업을 시뮬레이션합니다.

    weather_data = {
        "Seoul": {"temperature": 25, "condition": "맑음", "humidity": 60},
        "Busan": {"temperature": 28, "condition": "흐림", "humidity": 75},
        "Jeju": {"temperature": 22, "condition": "비", "humidity": 90},
    }

    weather = weather_data.get(city, {"error": "해당 도시의 날씨 정보를 찾을 수 없습니다."})

    return {"city": city, "weather": weather}

if __name__ == "__main__":
    mcp.run() 