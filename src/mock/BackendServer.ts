import express, { Request, Response } from 'express';
import logger from '../logging/Logger';

export class BackendServer {
  private app: express.Application;
  private port: number;
  private server?: ReturnType<typeof this.app.listen>;

  constructor(port: number = 4000) {
    this.app = express();
    this.port = port;
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(express.json());
  }

  private setupRoutes(): void {
    // Health check endpoint
    this.app.get('/health', (_req: Request, res: Response) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'backend',
      });
    });

    // Public endpoint (no auth required in backend, gateway handles it)
    this.app.get('/api/public', (_req: Request, res: Response) => {
      res.status(200).json({
        message: 'Public endpoint - accessible to all',
        timestamp: new Date().toISOString(),
      });
    });

    // Protected resource endpoint
    this.app.get('/api/protected', (req: Request, res: Response) => {
      // In a real scenario, the gateway would have already validated the JWT
      // and might forward user info in headers
      const userId = req.headers['x-user-id'] || 'anonymous';

      res.status(200).json({
        message: 'Protected resource accessed successfully',
        userId,
        timestamp: new Date().toISOString(),
        data: {
          secret: 'This is sensitive data',
          resourceId: '12345',
        },
      });
    });

    // User data endpoint
    this.app.get('/api/users/:id', (req: Request, res: Response) => {
      const { id } = req.params;

      res.status(200).json({
        userId: id,
        name: `User ${id}`,
        email: `user${id}@example.com`,
        timestamp: new Date().toISOString(),
      });
    });

    // POST endpoint for testing
    this.app.post('/api/data', (req: Request, res: Response) => {
      const data = req.body;

      res.status(201).json({
        message: 'Data received successfully',
        receivedData: data,
        timestamp: new Date().toISOString(),
      });
    });

    // Catch-all 404
    this.app.use((_req: Request, res: Response) => {
      res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource does not exist',
      });
    });
  }

  public start(): void {
    this.server = this.app.listen(this.port, () => {
      logger.info(`Mock backend server listening on port ${this.port}`);
    });
  }

  public stop(): void {
    if (this.server) {
      this.server.close(() => {
        logger.info('Mock backend server stopped');
      });
    }
  }

  public getPort(): number {
    return this.port;
  }
}
