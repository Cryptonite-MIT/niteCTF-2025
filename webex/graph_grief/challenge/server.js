require('dotenv').config();
const axios = require('axios');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const { ApolloServerPluginDrainHttpServer } = require('@apollo/server/plugin/drainHttpServer');
const express = require('express');
const http = require('http');
const path = require('path');
const libxmljs = require('libxmljs');
const fs = require('fs');
const typeDefs = fs.readFileSync(path.join(__dirname, 'schema.graphql'), 'utf8');
const resolvers = require('./resolvers');
const rejectFileXxe = require('./lib/reject-file-xxe');
const internalFileRouter = require('./lib/internal-file');

async function startServer() {
  const app = express();
  const httpServer = http.createServer(app);

  app.get('/internal/graphql', async (req, res) => {
    const ip = (req.ip || req.connection.remoteAddress || '').replace('::ffff:', '');
    if (ip !== '127.0.0.1' && ip !== '::1') {
      return res.status(403).send('forbidden');
    }

    const query = req.query.query;
    if (!query) return res.status(400).send('missing query');

    try {
      const result = await server.executeOperation(
        { query },
        { contextValue: { req } }
      );

      if (result.body.kind === 'single') {
        res.json(result.body.singleResult);
      } else {
        res.status(500).send('Streaming not supported in internal helper');
      }
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.use('/internal', internalFileRouter);

  app.use(express.raw({ type: 'application/xml', limit: '256kb' }));

  app.use(express.json());

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: false,
    plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
  });

  await server.start();

  const gqlMiddleware = expressMiddleware(server, {
    context: ({ req }) => ({ req }),
  });

  app.use(rejectFileXxe);
  app.post('/graphql', async (req, res, next) => {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    if (ct.includes('application/xml')) {
      try {
        let xml = req.body && req.body.toString('utf8');
        if (!xml) return res.status(400).send('Missing XML body');

        const firstTag = xml.indexOf('<');
        if (firstTag > 0) {
          xml = xml.substring(firstTag);
        }

        const doctypeMatch = xml.match(/<!ENTITY\s+%\s*([a-zA-Z0-9_]+)\s+SYSTEM\s+["']([^"']+)["']/i);
        if (doctypeMatch && doctypeMatch[2]) {
          const entityName = doctypeMatch[1];
          const remoteUrl = doctypeMatch[2];


          if (!/^https?:\/\//i.test(remoteUrl)) {

            return res.status(400).send('Only http(s) remote DTDs allowed');
          }
          let r;
          try {
            r = await axios.get(remoteUrl, {
              timeout: 5000,
              responseType: 'text',
              maxContentLength: 64 * 1024,
              validateStatus: s => s >= 200 && s < 400
            });

          } catch (err) {

            return res.status(400).send('Failed to fetch remote DTD');
          }

          if (!r || !r.data) {
            return res.status(400).send('Failed to fetch remote DTD');
          }

          if (/file:\/\//i.test(r.data) || /<!ENTITY\s+.*?\bSYSTEM\s+["'](?!(?:https?:\/\/|%))/i.test(r.data)) {

            return res.status(400).send('Remote DTD contains blocked schemes');
          }
          const defRegex = new RegExp(`<!ENTITY\\s+%\\s*${entityName}\\s+SYSTEM\\s+["'][^"']+["']\\s*>`, 'i');
          let xmlInlined = xml.replace(defRegex, r.data);

          xmlInlined = xmlInlined.replace(new RegExp(`%${entityName};`, 'g'), '');

          const systemEntityRegex = /<!ENTITY\s+(\w+)\s+SYSTEM\s+["']([^"']+)["']\s*>/g;
          let systemMatch;
          while ((systemMatch = systemEntityRegex.exec(xmlInlined)) !== null) {
            const entityName = systemMatch[1];
            const entityUrl = systemMatch[2];



            if (/^https?:\/\/(127\.0\.0\.1|localhost):8000\//.test(entityUrl)) {
              try {

                const entityData = await axios.get(entityUrl, {
                  timeout: 3000,
                  responseType: 'text',
                  maxContentLength: 1024 * 1024
                });

                if (entityData && entityData.data) {

                  const inlineEntity = `<!ENTITY ${entityName} "${entityData.data.replace(/"/g, '&quot;')}">`;
                  xmlInlined = xmlInlined.replace(systemMatch[0], inlineEntity);
                }
              } catch (err) {

              }
            } else {

            }
          }



          const doc = libxmljs.parseXmlString(xmlInlined, {
            noent: true,
            dtdload: false,
            nonet: false,
            dtdvalid: true
          });
          const text = (doc.root() && doc.root().text()) || '';
          return res.status(200).type('text/plain').send(text);
        }


        const doc = libxmljs.parseXmlString(xml, {
          noent: false,
          dtdload: false,
          nonet: true,
          dtdvalid: false
        });
        const text = (doc.root() && doc.root().text()) || '';
        return res.status(200).type('text/plain').send(text);

      } catch (err) {

        return res.status(400).json({ error: 'XML parse failed', message: err.message.substring(0, 100) });
      }
    } else {
      gqlMiddleware(req, res, next);
    }
  });

  app.get('/graphql', gqlMiddleware);

  app.use(express.static(path.join(__dirname, 'public')));

  app.use('*', (req, res) => {
    res.status(404).json({
      error: 'Quantum tunnel not found',
      message: 'The requested quantum pathway does not exist',
    });
  });

  const PORT = process.env.PORT || 8000;
  await new Promise(resolve => httpServer.listen({ port: PORT }, resolve));

}

startServer().catch(error => {

  process.exit(1);

});

