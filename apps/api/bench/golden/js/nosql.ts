import express from "express";
import { db, User } from "./models";

const app = express();

// ---- NoSQL injection (MongoDB / Mongoose) ------------------------------------
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password }); // VULN: NOSQL
  res.json(user);
});

app.patch("/reviews", async (req, res) => {
  const result = await db.reviews.updateMany( // ALSO: NOSQL
    { _id: req.body.id }, // VULN: NOSQL
    { $set: { message: req.body.message } },
  );
  res.json(result);
});

app.get("/products", async (req, res) => {
  const filter = { category: req.query.category };
  res.json(await db.products.find(filter)); // VULN: NOSQL
});

app.get("/orders/:id", async (req, res) => {
  res.json(await db.orders.find({ $where: "this.orderId === '" + req.params.id + "'" })); // VULN: NOSQL
});

app.post("/safe-login", async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) }); // SAFE: NOSQL
  res.json(user);
});

app.get("/safe-orders/:id", async (req, res) => {
  res.json(await db.orders.findOne({ orderId: req.params.id })); // SAFE: NOSQL
});

app.post("/profile", async (req, res) => {
  const user = await User.findOne({ where: { id: req.body.id } }); // SAFE: NOSQL
  await user.update({ displayName: req.body.name }); // SAFE: NOSQL
  res.json(user);
});

// ---- Open redirect -----------------------------------------------------------
app.get("/out", (req, res) => {
  res.redirect(req.query.url as string); // VULN: REDIRECT
});

app.get("/login-done", (req, res) => {
  const next = String(req.query.next);
  if (!next.startsWith("/")) return res.redirect("/");
  res.redirect(next); // SAFE: REDIRECT
});

app.get("/home", (_req, res) => {
  res.redirect("/dashboard"); // SAFE: REDIRECT
});

export default app;
