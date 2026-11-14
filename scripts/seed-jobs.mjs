import { MongoClient } from 'mongodb';
import 'dotenv/config';

const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const dbName = process.env.DB_NAME || 'hireloopdb';
const collectionName = process.env.JOBS_COLLECTION || 'job';

const now = Date.now();

const jobs = [
  {
    title: 'Senior Frontend Developer',
    companyName: 'TechNova',
    logoUrl: null,
    location: 'San Francisco, CA',
    remote: true,
    type: 'Full-time',
    workMode: 'Hybrid',
    level: 'Senior',
    salaryMin: 140000,
    salaryMax: 180000,
    currency: 'USD',
    easyApply: true,
    hot: true,
    createdAt: new Date(now - 1000 * 60 * 60 * 26),
  },
  {
    title: 'Backend Engineer (Go)',
    companyName: 'DataFlow',
    logoUrl: null,
    location: 'New York, NY',
    remote: true,
    type: 'Full-time',
    workMode: 'Remote',
    level: 'Mid',
    salaryMin: 150000,
    salaryMax: 200000,
    currency: 'USD',
    easyApply: false,
    hot: false,
    createdAt: new Date(now - 1000 * 60 * 60 * 50),
  },
  {
    title: 'Product Designer',
    companyName: 'PixelWorks',
    logoUrl: null,
    location: 'Remote',
    remote: true,
    type: 'Contract',
    workMode: 'Remote',
    level: 'Junior',
    salaryMin: 90000,
    salaryMax: 120000,
    currency: 'USD',
    easyApply: true,
    hot: false,
    createdAt: new Date(now - 1000 * 60 * 60 * 80),
  },
  {
    title: 'DevOps Engineer',
    companyName: 'CloudNine',
    logoUrl: null,
    location: 'Austin, TX',
    remote: false,
    type: 'Full-time',
    workMode: 'On-site',
    level: 'Senior',
    salaryMin: 160000,
    salaryMax: 210000,
    currency: 'USD',
    easyApply: false,
    hot: true,
    createdAt: new Date(now - 1000 * 60 * 60 * 110),
  },
  {
    title: 'Mobile Developer (React Native)',
    companyName: 'AppCraft',
    logoUrl: null,
    location: 'Los Angeles, CA',
    remote: true,
    type: 'Freelance',
    workMode: 'Remote',
    level: 'Mid',
    salaryMin: 80000,
    salaryMax: 110000,
    currency: 'USD',
    easyApply: false,
    hot: false,
    createdAt: new Date(now - 1000 * 60 * 60 * 140),
  },
  {
    title: 'Engineering Intern',
    companyName: 'StartupX',
    logoUrl: null,
    location: 'Remote',
    remote: true,
    type: 'Internship',
    workMode: 'Remote',
    level: 'Junior',
    salaryMin: 30000,
    salaryMax: 45000,
    currency: 'USD',
    easyApply: true,
    hot: false,
    createdAt: new Date(now - 1000 * 60 * 60 * 170),
  },
];

const run = async () => {
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(dbName);
  const collection = db.collection(collectionName);

  await collection.deleteMany({});
  const result = await collection.insertMany(jobs);

  console.log(`Seeded ${result.insertedCount} jobs into "${collectionName}".`);
  await client.close();
};

run().catch((err) => {
  console.error('Seed failed:', err?.message ?? err);
  process.exit(1);
});
