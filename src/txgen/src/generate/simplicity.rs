use core::mem;
use std::sync::Arc;

use super::{Generate, Sampled, Seeder};
use crate::seeder::u3;
use crate::simplicity_utils::value_for_type;

use simplicity::dag::{InternalSharing, PostOrderIterItem};
use simplicity::jet::{Elements, Jet};
use simplicity::node::{self, RedeemNode, WitnessNode};
use simplicity::node::{
    CoreConstructible as _, DisconnectConstructible as _, JetConstructible,
    WitnessConstructible as _,
};
use simplicity::types;
use simplicity::Value;

const MAX_VALUE_BITS: usize = 4 * 1024;

impl Generate for Value {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        use simplicity::types::Final;

        let mut bits = s.bit_iter();

        let mut ret = None;
        let mut stack = vec![];
        for _ in 0..MAX_VALUE_BITS * 2 + (MAX_VALUE_BITS + 1) / 2 {
            match bits.next_u3() {
                Some(u3::_0) => stack.push(Value::unit()),
                Some(u3::_1) => match stack.pop() {
                    Some(elem) => stack.push(Value::left(elem, Final::unit())),
                    None => break,
                },
                Some(u3::_2) => match stack.pop() {
                    Some(elem) => stack.push(Value::right(Final::unit(), elem)),
                    None => break,
                },
                Some(u3::_3) => match (stack.pop(), stack.pop()) {
                    (Some(r_elem), Some(l_elem)) => stack.push(Value::product(l_elem, r_elem)),
                    _ => break,
                },
                _ => break,
            }

            ret = Some(stack.last().unwrap().shallow_clone());
        }

        // We do a poor approximation of the size of a Value. But
        // we limit the total size above so it doesn't really matter.
        ret.map(|ret| Sampled {
            size: mem::size_of::<Value>() * ret.compact_len(),
            data: ret,
        })
    }
}

impl Generate for simplicity::Cmr {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        Generate::sample_then_map(s, simplicity::Cmr::from_byte_array)
    }
}

impl Generate for simplicity::FailEntropy {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        Generate::sample_then_map(s, simplicity::FailEntropy::from_byte_array)
    }
}

/// Maximum number of nodes in a WitnessNode before we start scaling back.
const MAX_NODES: usize = 1 * 64;

// You probably don't want to generate this. You probably want to generate
// a RedeemNode below, which additionally forces the thing to 1-1 and gives
// you the encode_to_vec function.
impl Generate for Arc<WitnessNode<Elements>> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        type Node = Arc<WitnessNode<Elements>>;

        macro_rules! try_break {
            ($res:expr) => {
                match $res {
                    Some(x) => x,
                    None => break,
                }
            };
        }

        // We build recursive structures by maintaining a stack of three elements.
        // If there are less than 3, we add a leaf node. If there are three, then
        // we combine a fuzzer-guided pair of them in a fuzzer-guided order with
        // a fuzzer-guided combinator.

        let ctx = types::Context::new();
        let mut stack = vec![];
        for _ in 0..MAX_NODES / 8 {
            let one_child = !stack.is_empty();

            let x = try_break!(s.extract_u8());
            if stack.len() < 3 {
                match x {
                    0 => stack.push((1, Node::unit(&ctx))),
                    1 => stack.push((1, Node::iden(&ctx))),
                    2 => {
                        let word: Sampled<Value> = try_break!(Generate::sample(s));
                        if word.data.compact_len().count_ones() == 1 {
                            stack.push((1, Node::const_word(&ctx, word.data)))
                        } else {
                            stack.push((1, Node::scribe(&ctx, &word.data)))
                        }
                    }
                    3 => {
                        let ent = simplicity::FailEntropy::from_byte_array([
                            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                            0xde, 0xad, 0xbe, 0xef,
                        ]);
                        stack.push((1, Node::fail(&ctx, ent)))
                    }
                    4 => {
                        // Note: we set the witness to None here. When sampling a RedeemNode,
                        // with all types present, we will populate the witness with the right
                        // type.
                        stack.push((1, Node::witness(&ctx, None)))
                    }
                    5 if one_child => {
                        let (size, child) = stack.pop().unwrap();
                        stack.push((size + 1, Node::injl(&child)));
                    }
                    6 if one_child => {
                        let (size, child) = stack.pop().unwrap();
                        stack.push((size + 1, Node::injr(&child)));
                    }
                    7 if one_child => {
                        let (size, child) = stack.pop().unwrap();
                        stack.push((size + 1, Node::drop_(&child)));
                    }
                    8 if one_child => {
                        let (size, child) = stack.pop().unwrap();
                        stack.push((size + 1, Node::take(&child)));
                    }
                    // asserts require that child source target be a product.If they fail, fall back to take/drop
                    9 if one_child => {
                        let (size, child) = stack.pop().unwrap();
                        let cmr = try_break!(Generate::sample(s)).data;
                        stack.push((size + 2, Node::assertl(&Node::take(&child), cmr).unwrap()));
                    }
                    10 if one_child => {
                        let (size, child) = stack.pop().unwrap();
                        let cmr = try_break!(Generate::sample(s)).data;
                        stack.push((size + 2, Node::assertr(cmr, &Node::take(&child)).unwrap()));
                    }
                    // Have a "break early" condition so we're not always making max-size objects
                    11 if one_child => break,
                    x => {
                        let idx = ((usize::from(x >> 4) << 8)
                            + usize::from(try_break!(s.extract_u8())))
                            % Elements::ALL.len();
                        stack.push((1, Node::jet(&ctx, Elements::ALL[idx])))
                    }
                }
            } else if stack.len() == 3 {
                let stack1 = stack.pop().unwrap();
                let stack2 = stack.pop().unwrap();
                let stack3 = stack.pop().unwrap();
                debug_assert!(stack.is_empty());
                let children = match x & 0x0f {
                    1 => {
                        stack.push(stack3);
                        (stack1, stack2)
                    }
                    2 => {
                        stack.push(stack2);
                        (stack1, stack3)
                    }
                    3 => {
                        stack.push(stack3);
                        (stack2, stack1)
                    }
                    4 => {
                        stack.push(stack1);
                        (stack2, stack3)
                    }
                    5 => {
                        stack.push(stack2);
                        (stack3, stack1)
                    }
                    6 => {
                        stack.push(stack1);
                        (stack3, stack2)
                    }
                    _ => {
                        stack.push(stack3);
                        stack.push(stack2);
                        stack.push(stack1);
                        break;
                    }
                };

                let (lsize, lchild) = children.0;
                let (rsize, rchild) = children.1;
                match x >> 4 {
                    0 => {
                        // Comp requires lchild target == rchild source. We make one A x _ and the
                        // other _ x B.
                        let lchild = Node::pair(&lchild, &Node::witness(&ctx, None)).unwrap();
                        let rchild = Node::drop_(&rchild);
                        let node = Node::comp(&lchild, &rchild).unwrap();
                        stack.push((lsize + rsize + 4, node));
                    }
                    1 => {
                        // Pair requires both source types be producted by the same thing, and
                        // both target types to be the same. To make the targets be the same
                        // we can just pair by a witness on each side.
                        let lchild = Node::pair(&lchild, &Node::witness(&ctx, None)).unwrap();
                        let rchild = Node::pair(&Node::witness(&ctx, None), &rchild).unwrap();
                        // and to make the source types be producted we just take both.
                        let lchild = Node::take(&lchild);
                        let rchild = Node::take(&rchild);
                        let node = Node::case(&lchild, &rchild).unwrap();
                        stack.push((lsize + rsize + 7, node));
                    }
                    2 => {
                        // Pair requires both source types be the same. We can make them the same
                        // by converting one from A to A x _, and the other from B to _ x B.
                        let drop = Node::drop_(&lchild);
                        let take = Node::take(&rchild);
                        let node = Node::pair(&drop, &take).unwrap();
                        stack.push((lsize + rsize + 3, node));
                    }
                    3 => {
                        // Disconnect is the same as comp except that the lchild source also
                        // needs to be left-producted by 2^256. Do this with drop.
                        let lchild = Node::pair(&lchild, &Node::witness(&ctx, None)).unwrap();
                        let lchild = Node::drop_(&lchild);
                        let rchild = Node::drop_(&rchild);
                        let node = Node::disconnect(&lchild, &Some(Arc::clone(&rchild))).unwrap();
                        stack.push((lsize + rsize + 5, node));
                    }
                    _ => break,
                };
                assert_eq!(stack.len(), 2);
            } else {
                unreachable!()
            }

            let size_est = stack.iter().map(|(sz, _)| *sz).sum::<usize>();
            if size_est > MAX_NODES {
                break;
            }
        }

        let last = stack.pop()?;
        let (size, data) = stack.iter().fold(last, |(acc_sz, acc_node), (sz, node)| {
            // Just pair everything together, that's simplest.
            let drop = Node::drop_(&acc_node);
            let take = Node::take(&node);
            (acc_sz + sz + 3, Node::pair(&drop, &take).unwrap())
        });

        // We do a poor approximation of the size of a node. But
        // we limit the total size above so it doesn't really matter.
        Some(Sampled {
            size: size * mem::size_of::<Node>(),
            data,
        })
    }
}

struct WitnessPopulator<'s, S> {
    s: &'s mut S,
}

impl<'s, S: Seeder, J: Jet> node::Converter<node::Witness<J>, node::Witness<J>>
    for WitnessPopulator<'s, S>
{
    type Error = std::convert::Infallible;

    fn convert_witness(
        &mut self,
        data: &PostOrderIterItem<&WitnessNode<J>>,
        wit: &Option<Value>,
    ) -> Result<Option<Value>, Self::Error> {
        debug_assert!(wit.is_none());
        let final_ty = data.node.arrow().target.finalize().unwrap();
        Ok(Some(value_for_type(self.s, final_ty.as_ref())))
    }

    fn convert_disconnect(
        &mut self,
        _data: &PostOrderIterItem<&WitnessNode<J>>,
        maybe_converted: Option<&Arc<WitnessNode<J>>>,
        _: &Option<Arc<WitnessNode<J>>>,
    ) -> Result<Option<Arc<WitnessNode<J>>>, Self::Error> {
        Ok(maybe_converted.map(Arc::clone))
    }

    fn convert_data(
        &mut self,
        data: &PostOrderIterItem<&WitnessNode<J>>,
        _: node::Inner<&Arc<WitnessNode<J>>, J, &Option<Arc<WitnessNode<J>>>, &Option<Value>>,
    ) -> Result<node::WitnessData<J>, Self::Error> {
        Ok(data.node.cached_data().clone())
    }
}

impl Generate for Arc<RedeemNode<Elements>> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        type WitNode = Arc<WitnessNode<Elements>>;

        let mut wit = WitNode::sample(s)?;
        let ctx = wit.data.arrow().inference_context.shallow_clone();
        let ty_unit = simplicity::types::Type::unit(&ctx);
        // Set target to unit
        if ctx.unify(&wit.data.arrow().target, &ty_unit, "").is_err() {
            let nd_unit = WitNode::unit(&ctx);
            wit.data = WitNode::comp(&wit.data, &nd_unit).unwrap();
        }

        // Set source to unit
        let source_ty = match wit.data.arrow().source.finalize() {
            Ok(ty) => ty,
            // Not sure what to do with occurs-check errors since we can't really serialize them
            Err(simplicity::types::Error::OccursCheck { .. }) => return None,
            _ => unreachable!(),
        };
        if !source_ty.is_unit() {
            let nd_wit = WitNode::witness(&ctx, None);
            wit.data = WitNode::comp(&nd_wit, &wit.data).unwrap();
        }

        //        println!("{}", wit.data);
        // Set all witness data.
        wit.data = wit.data.prune_and_retype();
        wit.data = wit
            .data
            .convert::<InternalSharing, _, _>(&mut WitnessPopulator { s })
            .unwrap();
        Some(wit.map(|data| data.finalize().unwrap()))
    }
}
