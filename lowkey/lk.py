        values.append(value)
    if mode=="encode": run_cast(["calldata",signature,*values],config)
    elif mode=="send": run_cast(["send",signature,*values,"--confirm"],config)
    else: run_cast(["call",signature,*values],config)

def run_replay(config,args):
    if not args:
        print("Usage: lk replay <transaction-hash> [trace flags...]"); return
    run_trace(config,args)

def run_fork(args):
    if not args:
        print("Usage: lk fork <rpc-url> [block-number]"); return
    rpc=args[0]
    command=["anvil","--fork-url",rpc]
    if len(args)>1: command.extend(["--fork-block-number",args[1]])
    print("Start a local fork with:")
    print("  "+redact_secrets(shlex.join(command)))
    print("Then point LowkeyCast at it:")
    print("  lk rpc http://127.0.0.1:8545")

def print_help():
    print("""
Lowkey — your Solidity audit sidekick

START HERE
  lk --h                         Show this menu
  lk doctor                     Check Foundry, Cast, Anvil, Python
  lk status                     Show target, RPC, actor, ABI
  lk accounts                   Show Anvil accounts + who owns each
  lk actor                      Pick an Anvil account interactively

  Example:
    lk actor                    -> choose 0 and name it Alice
    lk actor 0 Alice            -> use Anvil account 0 as Alice
    lk actor 1 Bob              -> use Anvil account 1 as Bob

AUDIT A CONTRACT
  lk scan <file|dir>            Find high-signal Solidity review markers
  lk deps [dir]                 Show imports/inheritance across the project
  lk layout <Contract>          Show storage slots
  lk risk                       Rank functions by review surface