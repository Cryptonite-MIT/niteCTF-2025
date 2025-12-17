const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();

function remoteIsLocal(req) {
    const ip = (req.ip || req.connection.remoteAddress || '').replace('::ffff:', '');
    return ip === '127.0.0.1' || ip === '::1';
}

router.get('/file', (req, res) => {

    if (!remoteIsLocal(req)) {

        return res.status(403).send('forbidden');
    }

    const name = req.query.name;
    if (!name) {
        return res.status(400).send('missing name');
    }

    if (name !== 'schema.graphql') {
        return res.status(404).send('not found');
    }
    const filePath = path.join(__dirname, '..', name);

    if (!fs.existsSync(filePath)) {
        return res.status(404).send('not found');
    }

    try {
        const fileContent = fs.readFileSync(filePath);
        const b64 = fileContent.toString('base64');


        res.type('text/plain').send(b64);

    } catch (err) {

        res.status(500).send('internal error');
    }
});

module.exports = router;