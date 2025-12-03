---
title: "1.8 Spec-generated docs"
permalink: /publishingapidocs1-8/
course: "Publishing API documentation"
weight: 1.8
---

<a href="http://editor.swagger.io/"><img src="{{ "/images/publishingapidocs/swagger-editor-example.png" | prepend: site.baseurl }}" alt="Swagger online editor" /></a>

## Specs replace program-specific doc blocks

With REST APIs, the platform and architecture behind the API can be in any programming language. This makes it difficult for tools to parse through comments within the code and run them through the same processing.

However, with content in a standard specification, the tools can read and parse the content. There are at least two main specifications:

* [Swagger](http://swagger.io/)
* [RAML](http://raml.org/)
* [API Blueprint](https://github.com/apiaryio/api-blueprint/blob/master/API%20Blueprint%20Specification.md)

Swagger is open source and has a strong community. RAML is more tied to Mulesoft's tooling platform. But both following generally the same principles.

There's also an API Blueprint spec.

## Swagger

In this part of the course, we'll dive more into Swagger. There are a few different pieces to get straight:

* [Swagger spec](https://github.com/swagger-api/swagger-spec)
* [Swagger editor](http://editor.swagger.io/#/)
* [Swagger-UI](https://github.com/swagger-api/swagger-ui)

There are a lot of other [Swagger services and tools](http://swagger.io/open-source-integrations/). You can actually describe the code of your API using Swagger annotations, and then generate the Swagger output that way. However, in this example, we'll create the spec manually that will drive the visual display.

## Some samples

Before we get into this tutorial, check out a few Swagger implementations:

* [Reverb](https://reverb.com/swagger#!/accounts).
* [VocaDB](https://github.com/swagger-api/swagger-codegen)
* [Watson Developer Cloud](http://www.ibm.com/smarterplanet/us/en/ibmwatson/developercloud/apis/)

Most of them look pretty much the same, with minimal branding. You'll notice the documentation is short and sweet in a Swagger implementation. This is because the Swagger display is meant to be an interactive experience where you can try out calls and see responses -- using your own API key to see your own data. It's the learn-by-doing-and-seeing-it approach.

## WORKSHOP ACTIVITY

In this activity, you'll create a Swagger UI display for the weatherdata endpoint in this [Mashape Weather API](https://www.mashape.com/fyhao/weather-13#weatherdata).

### Create a Swagger spec file

First we need to create a Swagger spec. 

1. Go to the [Swagger online editor](http://editor.swagger.io/#/).
2. Select **File > Open Example** and choose **PetStore Simple**. Click **Open**.
	
	You could just customize this sample YML file with the weatherdata endpoint documentation. However, to save you some time, you can just copy and paste the following into the Swagger editor:
	
	```
	swagger: '2.0'
    info:
      version: '1.0.0'
      title: Weather API
      description: A sample API that uses a Mashape weather API as an example to demonstrate features in the swagger-2.0 specification
      termsOfService: http://helloreverb.com/terms/
      contact:
        name: Your name
        email: youremail@mail.com
        url: http://swagger.io
      license:
        name: MIT
        url: http://opensource.org/licenses/MIT
    host: simple-weather.p.mashape.com
    schemes:
      - https
    consumes:
      - application/json
    produces:
      - application/json
    paths:
      /aqi:
        get:
          description: gets air quality index
          operationId: getWeatherData
          produces:
            - text/xml
            - text/html
          parameters:
            - name: lat
              in: query
              description: latitude
              required: false
              type: string
            - name: lng
              in: query
              description: longitude
              required: false
              type: string
          responses:
            '200':
              description: aqi response
            default:
              description: unexpected error
      /weather:
        get:
          description: gets weather forecast in short label
          operationId: getWeatherData
          produces:
            - text/xml
            - text/html
          parameters:
            - name: lat
              in: query
              description: latitude
              required: false
              type: string
            - name: lng
              in: query
              description: longitude
              required: false
              type: string
          responses:
            '200':
              description: aqi response
            default:
              description: unexpected error
      /weatherdata:
        get:
          description: Get weather forecast by Latitude and Longtitude
          operationId: getWeatherData
          produces:
            - application/json
            - application/xml
            - text/xml
            - text/html
          parameters:
            - name: lat
              in: query
              description: latitude
              required: false
              type: string
            - name: lng
              in: query
              description: longitude
              required: false
              type: string
          responses:
            '200':
              description: aqi response
            default:
              description: unexpected error
	```
	
	{{note}} YML syntax is a more human-readable form of JSON. Spacing matters! New levels appear existing text with two indented spaces. The colon indicates ano bject. Hyphens represent an array.{{end}}

3. Go to **File > Download JSON** and save the file as "swagger.json" on your computer.

### Set Up the Swagger UI

1. Download [Swagger UI](https://github.com/swagger-api/swagger-ui). Click the **Download ZIP** button and download the files to a convenient location on your computer. Extract the files.

	The only file you'll be working with here is the dist folder. Everything else is used only if you're regenerating the files. 
	
2. Drag the dist folder out of the swagger-ui-master folder.
3. Rename the dist folder to your name. My name is Tom, so I'll rename my folder to "tom."
3. Inside your "tom" folder, open index.html. 
4. Look for the following code:

	```
	$(function () {
	  var url = window.location.search.match(/url=([^&]+)/);
	  if (url && url.length > 1) {
	    url = decodeURIComponent(url[1]);
	  } else {
	    url = "http://petstore.swagger.io/v2/swagger.json";
	  }
	```
5. Change the `url` value to the following: `"http://69.195.124.51/~idrathe1/workshopuploads/tom/swagger.json";`.

In the `url` value, change "tom" to your name. This path is where you will upload your swagger file. Unfortunately, you can't run Swagger locally because it requires an http path in the URL. You will be uploading these files into this web host location. (This web host doesn't have a very friendly path -- sorry.)

6. The Mashape API also requires a header authorization, so you'll need to make another change.  Scroll down until you find the `addApiKeyAuthorization` function:

```
      function addApiKeyAuthorization(){
        var key = encodeURIComponent($('#input_apiKey')[0].value);
        if(key && key.trim() != "") {
            var apiKeyAuth = new SwaggerClient.ApiKeyAuthorization("api_key", key, "query");
            window.swaggerUi.api.clientAuthorizations.add("api_key", apiKeyAuth);
            log("added key " + key);
        }
```

Change the line ` window.swaggerUi.api.clientAuthorizations.add("api_key", apiKeyAuth);` to `("X-Mashape-Key", "BTdeRzJ8h9rxmhtkEfGpj3pb7qRyu1MoALFoxsivNUgZ9s2jJY", "header"));`, so that it looks like this:

```
      function addApiKeyAuthorization(){
        var key = encodeURIComponent($('#input_apiKey')[0].value);
        if(key && key.trim() != "") {
            var apiKeyAuth = new SwaggerClient.ApiKeyAuthorization("api_key", key, "query");
            swaggerUi.api.clientAuthorizations.add("key", new SwaggerClient.ApiKeyAuthorization("X-Mashape-Key", "BTdeRzJ8h9rxmhtkEfGpj3pb7qRyu1MoALFoxsivNUgZ9s2jJY", "header"));
            log("added key " + key);
        }
```

The `BTdeRzJ8h9rxmhtkEfGpj3pb7qRyu1MoALFoxsivNUgZ9s2jJY` is my Mashape API test key. You can swap in your own here if you have one (from the previous course) or use this one.

7. Uncomment out the lines here by removing the `/*` and `*/`.

```
// if you have an apiKey you would like to pre-populate on the page for demonstration purposes...
  /*
    var apiKey = "myApiKeyXXXX123456789";
    $('#input_apiKey').val(apiKey);
  */
```
8. Add in your API key, like this:

```
var apiKey = "BTdeRzJ8h9rxmhtkEfGpj3pb7qRyu1MoALFoxsivNUgZ9s2jJY";
$('#input_apiKey').val(apiKey);    
```

9. Save the file.
10. Drag the **swagger.json** file that you created earlier into the same directory as the index.html file you just edited.

{{tip}} If the above instructions didn't work out, just go to <a href="http://69.195.124.51/~idrathe1/workshopuploads/tom/index.html">http://69.195.124.51/~idrathe1/workshopuploads/tom/index.html</a>, right-click to view the source, and then copy the text.{{end}}

### Upload the Files to a Web Host

1. Download and install [Filezilla](https://filezilla-project.org/), unless you already have another FTP editor you're used to working with.
2. Go to **File > Site Manager** and create a new site.
3. Enter the following information:
	
	host: 69.195.124.51
	protocol: ftp
	user: stcsummit@idratherbewriting.com
	pass: apiworkshop2015
	
4. Click **Connect**.
5. Upload your "tom" folder into the directory that you connect into by default.
6. Now view your site: <a href="http://69.195.124.51/~idrathe1/workshopuploads/tom">http://69.195.124.51/~idrathe1/workshopuploads/tom</a>, replacing "tom" with your name.

<a href="http://69.195.124.51/~idrathe1/workshopuploads/tom/#/"><img src="{{ "/images/publishingapidocs/swaggertom.png" | prepend: site.baseurl }}" alt="Swagger instance" /></a>

### Interact with the Swagger UI

1. Go to Google Maps and search for an address.
2. Get the latitude and longitude from the URL, and plug it into your Swagger UI. For example, (37.3708905, -121.9675525 is Santa Clara). 
3. Click **Try it out**.

If successful, you should see something in the response body like this:

```
17 c, Partly Cloudy at Santa Clara, United States
```

Try working with each of your endpoints and see the data that gets returned.

## YML tutorial

When you created the Swagger spec file, you used a syntax called YML. YML stands for "YAML Ain't Markup Language." YML is easier to work with because it removes the brackets and curly braces that get in the way of reading content. In other words, YML is an attempt to create a more human readable data exchange format. It's similar to JSON but without the curly braces and brackets. Many computers ingest data in a YML or JSON format.

With a YML file, spacing is significant. This is a new object level:

```
level1:
  level2:
    level3:
```

To create a new level, indent two spaces. 

Each level can contain either a single value or an array:

```
---
  level3: 
    - 
      itema: "one"
      itemameta: "two"
    - 
      itemb: "three"
      itembmeta: "four"
```
        
Converted to JSON, level3 would look like this:

```
{
  "level3": [
    {
      "itema": "one",
      "itemameta": "two"
    },
    {
      "itemb": "three",
      "itembmeta": "four"
    }
  ]
}
```
        
If you learn how YML translates JSON syntax, it reduces the complexity of this format. 

## Swagger libraries

Swagger can also be implemented directly in the code. There are many Swagger libraries for different code bases. If your developers want to integrate Swagger at the code level, they add certain annotations directly in the code. Swagger libraries can then parse the annotations and generate the same spec file that you produced manually using the earlier steps. [Swagger codegen](https://github.com/swagger-api/swagger-codegen) parses the annotations to create the swagger spec from your code.

By integrating Swagger into the code, you allow developers to easily write documentation, make sure new features are always documented, and keep the documentation more current.

The annotation methods for Swagger doc blocks vary based on the programming language.

## Limitations with spec-driven documentation

Notice a few limitations with Swagger: 

* There's not much room to describe in detail the workings of the endpoint.
* Making links or other markup in the YML file will require you to add some escape characters (`\`).



