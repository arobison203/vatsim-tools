/**
 * Code snippet used to verify a VATUSA ULS token.
 * 
 * @var THE_TOKEN: Token recieved from VATUSA
 * @var JWK_KEY: "k" field in the JSON JWK provided by VATUSA
 */


const tokenParts = THE_TOKEN.split('.');

const sig = b64(
    crypto.createHmac('sha256', new Buffer.from(JWK_KEY, 'base64'))
    .update(`${tokenParts[0]}.${tokenParts[1]}`)
    .digest()
);

if(sig == tokenParts[2]) { // compare our generated signature to the signature recieved from VATUSA.
    const token = JSON.parse(Buffer.from(tokenParts[1], 'base64'));
    if(token.iss === 'VATUSA' && token.aud === '') { // Update token.aud to your ARTCC
        const {data} = await axios.get(`https://login.vatusa.net/uls/v2/info?token=${tokenParts[1]}`).catch(err => {
            console.log(err); // you should probably handle the error better than this.
            return false;
        });

        if(data) {
            //got a good response from VATUSA, process login.
            return;
        } else {
            console.log('Bad response from VATUSA, discarding.');
            res.status(500).json({errCode: 'ERR_BAD_VATUSA'});
            return;
        }
    } else {
        console.log('Token not from VATUSA/ZAB, discarding.');
        res.status(500).json({errCode: 'ERR_BAD_TOKEN'});
        return;
    }
} else {
    console.log(`Our signature didn't match VATUSA, discarding.`);
    res.status(500).json({errCode: 'ERR_BAD_SIG'});
    return;
}
