# Authentication Backend
Sample Authentication Service built with Spring Boot, Security(with JWT) and MYSQL
## Prerequisites
1. Java 11
2. Gradle 7.0
3. Maildev
4. Docker/MYSQL
## How to use this code
1. Clone this repo
2. Navigate to ``authentication-backend`` folder
3. Install all project dependencies
4. Set Up MYSQLDB or run following Docker command
```
docker run --name auth_database -e MYSQL_ROOT_PASSWORD=root -e MYSQL_USER=app_user -e MYSQL_PASSWORD=root -p 3306:3306 -e MYSQL_DATABASE=auth_database -d mysql
```
5. Run ``Maildev``. If you don't have maildev run following command
```
npm install -g maildev
```
then
```
maildev
```
You can navigate to ``http://localhost:1080`` in your browser

6. Start the Application and navigate to ``http://localhost:8080/swagger-ui.html``
   in your browser.
## Built with
* Java 11
* Spring Boot 2
* MySQL 8
* JWT
* Spring Security
* Swagger
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.