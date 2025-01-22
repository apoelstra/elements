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
// You probably don't want to generate this. You probably want to generate
// a RedeemNode below, which additionally forces the thing to 1-1 and gives
// you the encode_to_vec function.
impl Generate for Arc<WitnessNode<Elements>> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        type Node = Arc<WitnessNode<Elements>>;

        let ctx = types::Context::new();
        u16::sample_then_map(s, |n| {
            Node::jet(&ctx, Elements::ALL[usize::from(n) % Elements::ALL.len()])
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
