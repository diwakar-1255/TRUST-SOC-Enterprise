"use client";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { request } from "@/lib/api";

export default function LoginPage() {
  const [email,setEmail]=useState("admin@example.com"); const [password,setPassword]=useState(""); const [error,setError]=useState(""); const router=useRouter();
  async function submit(e:FormEvent){e.preventDefault();setError("");try{const data=await request<{access_token:string;refresh_token:string}>("/auth/login",{method:"POST",body:JSON.stringify({email,password})});localStorage.setItem("access_token",data.access_token);localStorage.setItem("refresh_token",data.refresh_token);router.push("/");}catch(err){setError(err instanceof Error?err.message:"Login failed");}}
  return <div className="login"><form className="card login-card" onSubmit={submit}><div className="brand">TRUST-SOC<small>SECURE ACCESS</small></div><h1 style={{marginTop:28}}>SOC validation console</h1><p className="subtitle">Use the bootstrap account, then rotate credentials immediately.</p><label className="field">Email<input value={email} onChange={e=>setEmail(e.target.value)} autoComplete="username" /></label><label className="field">Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password" /></label><button className="primary">Sign in</button>{error&&<p className="error">{error}</p>}</form></div>;
}
