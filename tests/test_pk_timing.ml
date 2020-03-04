(* the struggle is:
   Kocher @ Crypto 1996 "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems"
   https://www.paulkocher.com/TimingAttacks.pdf

   Brumley, Boneh @ Usenix Security 203 "Remote Timing Attacks are practicable"
   http://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf

   Percival @ 2005 "Cache Missing for Fun and Profit"
   http://www.daemonology.net/papers/htt.pdf
*)

(* the ultimate goal of a timing side-channel attack is to leak the private key
   (or exponent) of a cryptosystem *)

(* this module attempts to gathers some computational timing statistics with
   the various available mitigations:

   (a) no mitigation <- computational time is expected to vary depending on the key
   (b) blinding (multiply with random) <- computational time is expected to be uniform (2-10% slower according to papers above)
   (c) use Z.powm_sec instead of Z.powm <- computational time is expected to be uniform (and slower than baseline)
   (d) blinding _and_ Z.powm_sec <- computational time is expected to be uniform and slow

   for gathering data, first N keys are produced (that hopefully differ in the
   number of bits set to 1). for each key:
   - time M times signing a message for each mitigation (the variation should be neglegible)
   - collect that timing number (let's say average and ensure there's "no" variation)

   now we have for each mitigation N durations for computing a signature, and
   look at variance within these.

   recording (a) is important to be able to evaluate the price we pay (in form
   of cpu cycles, which is equivalent to power) for the mitigations. *)

let bits = 2048

let to_sign = Cstruct.create_unsafe ((bits / 8) - 1)

let with_timer f =
  let now = Mtime_clock.now_ns () in
  ignore (f to_sign);
  let now' = Mtime_clock.now_ns () in
  Int64.sub now' now

(* this should be done better *)
let compute_sigs m f =
  let minimum = ref Int64.max_int and maximum = ref 0L and total = ref 0L in
  for _i = 1 to m do
    let dur = with_timer f in
    if dur < !minimum then minimum := dur;
    if dur > !maximum then maximum := dur;
    total := Int64.add !total dur
  done;
  let average = Int64.to_float !total /. float_of_int m in
  (average, Int64.to_float !minimum, Int64.to_float !maximum)

let jump _ n m =
  Mirage_crypto_rng_unix.initialize ();
  let keys = Array.init n (fun _ -> Mirage_crypto_pk.Rsa.generate bits) in
  let minimum = ref max_float and maximum = ref 0. in
  Array.iteri (fun i key ->
      let avg, min, max = compute_sigs m (Mirage_crypto_pk.Rsa.decrypt ~mask:`No ~key) in
      if avg < !minimum then minimum := avg;
      if avg > !maximum then maximum := avg;
      Logs.info (fun m -> m "%d (a) avg %f min %f max %f (nothing)" i avg min max))
    keys ;
  Logs.app (fun m -> m "(a) min %f max %f" !minimum !maximum);
  let minimum = ref max_float and maximum = ref 0. in
  Array.iteri (fun i key ->
      let avg, min, max = compute_sigs m (Mirage_crypto_pk.Rsa.decrypt ~mask:`Yes ~key) in
      if avg < !minimum then minimum := avg;
      if avg > !maximum then maximum := avg;
      Logs.info (fun m -> m "%d (b) avg %f min %f max %f (masking)" i avg min max))
    keys ;
  Logs.app (fun m -> m "(b) min %f max %f" !minimum !maximum);
  let minimum = ref max_float and maximum = ref 0. in
  Array.iteri (fun i key ->
      let avg, min, max = compute_sigs m (Mirage_crypto_pk.Rsa.decrypt ~powm_sec:true ~mask:`No ~key) in
      if avg < !minimum then minimum := avg;
      if avg > !maximum then maximum := avg;
      Logs.info (fun m -> m "%d (c) avg %f min %f max %f (powm_sec)" i avg min max))
    keys ;
  Logs.app (fun m -> m "(c) min %f max %f" !minimum !maximum);
  let minimum = ref max_float and maximum = ref 0. in
  Array.iteri (fun i key ->
      let avg, min, max = compute_sigs m (Mirage_crypto_pk.Rsa.decrypt ~powm_sec:true ~mask:`Yes ~key) in
      if avg < !minimum then minimum := avg;
      if avg > !maximum then maximum := avg;
      Logs.info (fun m -> m "%d (d) avg %f min %f max %f (powm_sec + masking)" i avg min max))
    keys ;
  Logs.app (fun m -> m "(d) min %f max %f" !minimum !maximum);
  Ok ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let n =
  let doc = "Number of keys" in
  Arg.(value & opt int 10 & info [ "keys" ] ~doc ~docv:"KEYS")

let m =
  let doc = "Signature iterations" in
  Arg.(value & opt int 1000 & info [ "iterations" ] ~doc ~docv:"ITER")

let cmd =
  Term.(term_result (const jump $ setup_log $ n $ m)),
  Term.info "oupdate" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
