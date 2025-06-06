#!/bin/bash

# MCP 서버 로깅과 함께 실행
echo "Starting MCP Weather Server with logging..."
echo "$(date): MCP Server starting" >> /app/mcp_server.log

# Python MCP 서버 실행
python /app/custom_mcp_server.py 2>&1 | tee -a /app/mcp_server.log &

# 서버 프로세스 ID 저장
echo $! > /app/mcp_server.pid

echo "MCP Server started with PID: $(cat /app/mcp_server.pid)"
echo "$(date): MCP Server started with PID: $(cat /app/mcp_server.pid)" >> /app/mcp_server.log

# 무한 대기 (컨테이너가 종료되지 않도록)
tail -f /app/mcp_server.log 