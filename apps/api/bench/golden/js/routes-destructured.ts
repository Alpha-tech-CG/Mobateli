import { Router, type Request, type Response } from "express";
import { db } from "./db";

const router = Router();

router.get("/users", async ({ query }: Request, res: Response) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${query.name}'`); // VULN: SQLI
  res.json(rows);
});

router.get("/go", (req: Request, res: Response) => {
  const { next } = req.query;
  res.redirect(String(next)); // VULN: REDIRECT
});

router.get("/profile/:id", async ({ params }: Request, res: Response) => {
  res.redirect("/users/" + params.id); // SAFE: REDIRECT
});

export default router;
