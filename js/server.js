const express = require('express');
const {auth, resolver, loaders} = require('@iden3/js-iden3-auth')
const getRawBody = require('raw-body')

const app = express();
const port = 8000;

app.use(express.static('static'));

app.get("/api/sign-in", (req, res) => {
    console.log('get Auth Request');
    GetAuthRequest(req,res);
});

app.post("/api/callback", (req, res) => {
    console.log('callback');
    Callback(req,res);
});

app.listen(port, () => {
    console.log('server running on port 8000');
});

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();
  // GetQR returns auth request
  async function GetAuthRequest(req,res) {
  // Audience is verifier id
  const hostUrl = "https://5a95-2605-6440-4000-a000-00-6e6c.ngrok.io"; //TODO: localhost:8000
  const sessionId = 1;
  const callbackURL = "/api/callback"
  const audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"

  const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;

  // Generate request for basic authentication
  const request = auth.createAuthorizationRequestWithMessage(
    'test flow',
    'message to sign',
    audience,
    uri,
  );
  
  request.id = '7f38a193-0918-4a48-9fac-36adfdb8b542';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';

  // Add request for a specific proof
  const proofRequest = {
    id: 1,
    circuit_id: 'credentialAtomicQuerySig',
    rules: {
      query: {
      allowedIssuers: ['1158FFCX2Dqd5Hy6G7uSw5Kcmzioz3euRiuhHeFnAH'],
      schema: {
        type: 'CScore',
        url: 'https://s3.eu-west-1.amazonaws.com/polygonid-schemas/b25bffc5-84ff-4ac7-87dc-1d9c40d4f311.json-ld',
      },
      req: {
        creditScore: {
          $gt: 900, // creditScore field great than 720
        },
      },
      },
    },
  };

  const scope = request.body.scope ?? [];
  request.body.scope = [...scope, proofRequest];

  // Store auth request in map associated with session ID
  requestMap.set(`${sessionId}`, request);

  return res.status(200).set('Content-Type', 'application/json').send(request);
}

// Callback verifies the proof after sign-in callbacks
async function Callback(req,res) {
  // Get session ID from request
  const sessionId = req.query.sessionId;
  // get JWZ token params from the post request
  const raw = await getRawBody(req);
  const tokenStr = raw.toString().trim();

  // fetch authRequest from sessionID
  const authRequest = requestMap.get(`${sessionId}`);
    
  // Locate the directory that contains circuit's verification keys
  const verificationKeyloader = new loaders.FSKeyLoader('../keys');
  const sLoader = new loaders.UniversalSchemaLoader('ipfs.io');

  // Add Polygon Mumbai RPC node endpoint - needed to read on-chain state and identity state contract address
  const ethStateResolver = new resolver.EthStateResolver(
    'https://polygon-mumbai.g.alchemy.com/v2/XU1AlAfY0g0HRHrfh7ykOGqOofGupyZm',
    '0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3'
  );

  // EXECUTE VERIFICATION
  const verifier = new auth.Verifier(
    verificationKeyloader,
    sLoader, ethStateResolver,
  );

  try {
    authResponse = await verifier.fullVerify(tokenStr, authRequest);
  } catch (error) {
    return res.status(500).send(error);
  }
  console.log(authResponse);
  console.log("user with ID: " + authResponse.from + " Succesfully authenticated")
  return res.status(200).set('Content-Type', 'application/json').send("user with ID: " + authResponse.from + " Succesfully authenticated");
}
