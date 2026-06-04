
qm.staticData.appSettings = {
    "appDesign": {
        "clientSecret": "AjXHyGVvBljV9V4hIcuaBs6c1XggzB38",
        "privateConfig": {
            "bugsnag_key": "hl7ij49k1285848342342ii5j321h2jm",
            "FOURSQUARE_CLIENT_SECRET": "CBWWFWQFQXV04EFUN5KZKQGY2IX0EDD5VDJLLFAMVVRVF1WF",
        }
    }
}

const client = algoliasearch('user', '7f4518df25cf869cee323bf312f02c89');


await setFormInput(
t,
'Stream key',
process.env.SLOBS_STREAM_KEY || 'live_147956788_EzVP5LjgcNbYwexq2lZrM4qFRb5BX6'
);


var promise = jsonp('http://dev.virtualearth.net/REST/v1/Locations', {
    parameters : {
        query : that._searchText,
        key : 'AkMnCOd4RF1U7D7qgdBz3Fk1aJB3rgCCI_DO841suDGxqOg0SMICTE8Ivy5HhAf5'

    },
    callbackParameterName : 'jsonp'
});

//Options
this.options = {
    api_key_flickr: 		"f2cc870b4d233dd0a5bfe73fd0d64ef0",
    api_key_googlemaps: 	"AIzaSyB9dW8e_iRrATFa8g24qB6BDBGdkrLDZYI",
    api_key_embedly: 		"", // ae2da610d1454b66abdf2e6a4c44026d
    credit_height: 			0,
    caption_height: 		0,
    background:             0   // is background media (for slide)
};
