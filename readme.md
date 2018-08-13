# Approximate Divisive Hierarchical Clustering (ADHIC) Tool for Server Event Logs

An interactive browser-based ADHIC decision tree monitoring tool, for analysis of the included web server access & error logs. Written in Javascript.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Make sure your server or device has the latest version of [node.js](https://nodejs.org/en/download/package-manager/) installed.

```
$ node --version
>v10.7.0
```

### Installing

Open any terminal and download or clone the following repository from github:

```
git clone "https://github.com/XZymo/4905-Log-Parser.git"
```

Navigate inside the repository and execute the following command to begin the application:

```
node app.js
```

The application will then display the execution of the algorithm, then notify that the application is running on port 3000. This signifies that the server is now active and the tree can be accessed via [http://localhost:3000/](http://localhost:3000/).

## Running the tests

Due to lack of access to a real-time server and a larger volume of testing data, the application's input data must be hard coded for testing purposes. 

### Access.log execution

Explain what these tests test and why

```
Give an example
```

### Error.log execution

Explain what these tests test and why

```
Give an example
```

## Deployment

For deployment, this app would require constant access to your server's event logs 

## Built With

* [node.js](https://nodejs.org/en/) - JavaScript run-time environment
* [express.js](https://expressjs.com/) - The web API framework used
* [npm](https://www.npmjs.com/) - JavaScript package anager
* [github](https://github.com/) - Repository and code management system

## Contributing

This application was developed without any contributions other than that of the author. For details on the process for submitting pull requests, please email [daniel.fitzhenry@carleton](daniel.fitzhenry@carleton.ca).

## Versioning

No official release yet planned.

## Author

* **Daniel Fitzhenry** - *Initial work* - [XZymo](https://github.com/XZymo)

See also the list of [contributors](https://github.com/XZymo/4905-Log-Parser/graphs/contributors) who participated in this project.

## License

N/A

## Acknowledgments

Based on the algorithm as proposed by Abdulrahman Hijazi in his Ph.D. thesis “[Network Traffic Characterization Using (p, n)-grams Packet Representation](http://people.scs.carleton.ca/~soma/pubs/students/abdulrahman-hijazi-phd.pdf)”
