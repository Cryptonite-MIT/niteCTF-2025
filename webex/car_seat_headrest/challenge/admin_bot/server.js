const express = require('express');
const Bot = require('./bot');

const app = express();
const PORT = process.env.PORT ;

app.use(express.json());

app.post('/simulate', async (req, res) => {
    const { attackerUrl } = req.body;

    if (!attackerUrl) {
        return res.status(400).json({ error: 'URL required' });
    }

    const b = new Bot();
    const result = await b.run(attackerUrl);

    res.json(result);
});

app.listen(PORT, () => {
    console.log(`Bot service running on port ${PORT}`);
});

module.exports = app;