use zk_ai_core::{AiEngine, ModelSpec, cosine_similarity};

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let cache_dir = std::env::temp_dir().join("kinshield-eval-cache");
        let mut engine = AiEngine::new(&cache_dir).await.unwrap();
        let spec = ModelSpec::e5_small_int8();
        engine.ensure_model(&spec).await.unwrap();

        let prototypes = [
            ("romance_grooming", "I have fallen in love with you after just a few days of chatting. You are my soulmate. I want to visit you but I need money for flights and visa fees. Can you send me money?"),
            ("authority_claim", "This is an official call from the police department. I am a government official. We are calling on behalf of the tax authority regarding your outstanding tax payments."),
            ("promise_high_return", "Join our investment group for guaranteed high returns. Professional traders will manage your funds with zero risk. You can double your money in just one week. Minimum investment is only $100."),
            ("charity_appeal", "Urgent appeal: victims of the recent disaster urgently need your help. Please donate now to provide food, water, and shelter. Every dollar goes directly to helping the victims."),
            ("family_emergency", "Mom, I'm in the hospital. I had an accident and need emergency surgery. Please send money for the medical bills right away. Don't tell dad. This is urgent."),
        ];

        // Pre-compute prototype embeddings
        println!("Computing prototype embeddings...");
        let mut proto_embs = Vec::new();
        for (name, text) in &prototypes {
            let prefixed = format!("query: {}", text);
            let emb = engine.run_embedding(&prefixed).await.unwrap();
            println!("  {} dim={} norm={:.4}", name, emb.len(), emb.iter().map(|v| v*v).sum::<f32>().sqrt());
            proto_embs.push((*name, emb));
        }

        // Test with a few scam and safe messages
        let tests = [
            ("SCAM", "URGENT: Your DBS account has been suspended due to unusual activity. Verify now at http://dbs-secure-login.xyz or your account will be permanently locked within 24 hours."),
            ("SCAM", "Dear customer, we detected unauthorized access to your Vietcombank account. Please confirm your identity immediately: http://vietcombank-verify.net"),
            ("SAFE", "Your Grab Unlimited Pass is expiring in 3 days. Renew now to keep enjoying unlimited rides."),
            ("SAFE", "Thank you for your purchase. Your order will arrive in 3-5 days."),
            ("SAFE", "Hi, are you free for dinner tonight? Thinking of trying that new Thai place at Tanjong Pagar."),
            ("SCAM", "I have fallen in love with you after just a few days. You are my soulmate. I need money for flights to visit you."),
            ("SAFE", "Anh oi, em vua doc duoc tin tuyen dung vi tri Digital Marketing tai Lazada."),
        ];

        println!("\nSimilarity scores:");
        println!("{:<8} {:<60}", "Label", "Text (first 60 chars)");
        for (name, _proto_emb) in &proto_embs {
            print!("{:<8} ", name);
        }
        println!();
        println!("{}", "-".repeat(120));

        for (label, text) in &tests {
            let prefixed = format!("query: {}", text);
            let emb = engine.run_embedding(&prefixed).await.unwrap();
            print!("{:<8} {:<60} ", label, &text[..text.len().min(60)]);
            for (_, proto_emb) in &proto_embs {
                let score = cosine_similarity(&emb, proto_emb);
                print!("{:.4}  ", score);
            }
            println!();
        }

        // Also check embedding norms and a few raw values
        let test1 = "query: URGENT: Your DBS account has been suspended.";
        let test2 = "query: Thank you for your purchase.";
        let emb1 = engine.run_embedding(test1).await.unwrap();
        let emb2 = engine.run_embedding(test2).await.unwrap();
        let norm1 = emb1.iter().map(|v| v*v).sum::<f32>().sqrt();
        let norm2 = emb2.iter().map(|v| v*v).sum::<f32>().sqrt();
        let sim = cosine_similarity(&emb1, &emb2);
        println!("\nRaw embedding check:");
        println!("  scam emb: dim={} norm={:.4} first5={:?}", emb1.len(), norm1, &emb1[..5]);
        println!("  safe emb: dim={} norm={:.4} first5={:?}", emb2.len(), norm2, &emb2[..5]);
        println!("  cosine_sim(scam, safe) = {:.4}", sim);
    });
}
