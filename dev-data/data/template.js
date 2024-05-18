const userRoles = ['user', 'admin', 'moderator', 'maintainer'];
// user can get a discount, login to watch purchase history, track purchase and leave a review on purchased prooduct
// admin can delete users create users with certain role, and allowed access to everything.
// moderator filters the reviews manually to filter out vioent and hate speech. can ban users.
// maintainer can create patch and delete products.

const users = [
  {
    role: 'user',
    fullName: 'Carl Jonson',
    email: 'carl@example.com',
    phone: '0524567878',
    city: 'Jerusalem',
    birthDate: '1996-09-02',
    history: [invoices],
    password: 'pass1234',
    passwordConfirm: 'pass1234',
    active: true,
  },
];

const invoices = [
  {
    user: '5c88fa8cf4afda39709b895a',
    products: ['5c88fa8cf4avda49709b895a', '5c88fa8cf4avda49709b116f'],
    date: Date.now(),
    isPaid: true,
    price: [400, 200],
    discount: 0.1,
    shipping: 15,
    totalprice: 555,
  },
];

const products = [
  {
    name: 'Intel core i7 cpu',
    slug: `intel-core-i7-cpu-${'HASH'}`,
    category: ['computers', 'cpu', 'i7'],
    tags: [],
    price: 400,
    discount: 0.1,
    pictures: ['pic.png'],
    description: 'Intel Core i7 14700K 3.4Ghz 33MB Cache s1700 - Tray',
    presentation: '<div> </div>',
    spicifications: [],
    active: true,
  },
];

const reviews = [
  {
    user: '5c88fa8cf4afda39709c295a',
    product: '5c8a1dfa2f8fb814b56fa181',
    title: 'A really powerful cpu',
    content:
      'I really love the performance and the efficency. This is the best value for the price!',
  },
];
