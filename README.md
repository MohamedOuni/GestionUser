# <span style="color:blue">Project Micro Service Employ Edge</span>

**Getting Started with Micro Service Architecture**

In this application we have a total of 8 microServices :


| MicroService         | Description |
|----------------------|-------------|
| Api-Gateway          | API management tool that sits between a client and a collection of backend services |
| Eureka-Server-MS     | This micro service is Our discovery Server |
| Task-Server          | This micro service is designed to manage all the Task |
| Project-Server       | This micro service is designed to manage all the Project |
| Leave-Server         | This micro service is designed to manage all the Leave |
| Intership-Server     | This micro service is designed to manage all the Intership |
| Claim-Server         | This micro service is designed to manage all the Claim |
| Event-Server         | This micro service is designed to manage all the events |



## MSs & their PORTS

| MicroService      | Local PORT |
|-------------------|------------|
| Eureka-Server     | 8051       |
| Api-Gateway       | 8761       |
| Task-MS           | 8890       |
| Project-MS        | 8898       |
| Leave-MS          | 8893       |
| Intership-MS      | 2020       |
| Claim-MS          | 8030       |
| Event-MS          | 5179       |


**How to run this application:**
1. Download the code of this repo
2. Install all the dependencies
3. Run `maven clean install` for all the micro services
4. Go to the root folder then run `docker-compose up`
