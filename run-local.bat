@echo off
setlocal
cd /d "%~dp0"
where java >nul 2>nul || (echo Java 17+ is required. & pause & exit /b 1)
where mvn  >nul 2>nul || (echo Maven is required - or open the project in IntelliJ IDEA / use Docker. & pause & exit /b 1)
echo Building (first build downloads dependencies, this can take a few minutes)...
call mvn -q -B -DskipTests package || (echo Build failed. & pause & exit /b 1)
start "user-service"  java -jar user-service\target\user-service.jar
start "order-service" java -jar order-service\target\order-service.jar
timeout /t 3 >nul
echo.
echo Gateway:   http://localhost:8080
echo Dashboard: http://localhost:8080/dashboard.html   (admin / admin123)
echo Demo user: demo / password123
echo Close the user-service and order-service windows to stop the backends.
echo.
java -jar gateway\target\gateway.jar
